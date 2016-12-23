/*
 * Copyright (c) 2016 Patrik Lundin <patrik@sigterm.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "ilsd.h"

/* Filled in by main() and used in process_arp_packet() */
struct in_addr network; /* The network our interface belongs to */
struct in_addr netmask; /* The netmask our interface uses */

/* Globally reachable database handle */
sqlite3 *db;

/* Globally reachable pcap session handle */
pcap_t *pcap_handle;

/* Global debug mode */
int debug;

void
signal_handler(int sig)
{
    pcap_breakloop(pcap_handle);
}

void usage(void)
{
    extern char *__progname;

    fprintf(stderr, "usage: %s [-d] [-i interface]\n",
        __progname);
    exit(1);
}

/*
 * Initialize syslog if not running in debug mode.
 */
void
init_syslog(void)
{
    extern char *__progname;

    if (!debug){
        openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }
}

/*
 * Write a log message to syslog or stderr based on debug mode.
 */
void
log_message(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if (debug) {
    	vfprintf(stderr, format, ap);
    	fprintf(stderr, "\n");
    	fflush(stderr);
    } else {
        vsyslog(priority, format, ap);
    }

    va_end(ap);
}

/*
 * Drop privileges to unprivileged user, done after pcap handle has been
 * opened.
 */
int
chroot_and_drop_privileges(char *user)
{
    struct passwd *pw;            /* Used for dropping privileges */

    if ((pw = getpwnam(user)) == NULL){
        log_message(LOG_CRIT,
            "getpwnam failed for user \"%s\", exiting", user);
        exit(1);
    }

    if (chroot(pw->pw_dir) == -1) {
        log_message(LOG_CRIT, "unable to chroot(%s), exiting", pw->pw_dir);
        exit(1);
    }
    if (chdir("/") == -1) {
        log_message(LOG_CRIT, "unable to chdir(\"/\"), exiting");
        exit(1);
    }

    if (setgroups(1, &pw->pw_gid) ||
        setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
        setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {

        log_message(LOG_CRIT, "dropping privileges to user %s failed, exiting",
            user);
        exit(1);
    }

    return 0;
}

/*
 * Open database, creating the table if necessary.
 */
int
open_ilsd_database(void){

    sqlite3_stmt *create_ilsd_table_stmt;
    int sqlite3_rc;

    /* Set up SQLite connection */
    sqlite3_rc = sqlite3_open("db/ilsd.db", &db);

    if(sqlite3_rc != SQLITE_OK){
        log_message(LOG_CRIT, "can't open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    /* Create ilsd table if it does not exist */
    sqlite3_rc = sqlite3_prepare_v2(
        db,
        "CREATE TABLE IF NOT EXISTS "
        "ilsd(ip TEXT PRIMARY KEY, mac TEXT NOT NULL, ts INT NOT NULL)",
        -1,
        &create_ilsd_table_stmt,
        NULL
    );
    if(sqlite3_rc != SQLITE_OK){
        log_message(LOG_CRIT,
            "can't prepare ilsd table: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    sqlite3_rc = sqlite3_step(create_ilsd_table_stmt);
    if(sqlite3_rc != SQLITE_DONE){
        log_message(LOG_CRIT,
            "can't create ilsd table: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    sqlite3_rc = sqlite3_finalize(create_ilsd_table_stmt);
    if(sqlite3_rc != SQLITE_OK){
        log_message(LOG_CRIT,
            "can't finalize ilsd table: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    return 0;
}

/*
 * Close the database.
 */
int
close_ilsd_database(void){

    int sqlite3_rc;

    sqlite3_rc = sqlite3_close(db);
    if(sqlite3_rc != SQLITE_OK){
        log_message(LOG_CRIT, "can't close ilsd db: %s", sqlite3_errmsg(db));
        return(1);
    }
    return 0;
}

/*
 * Add or update row in table
 */
int
update_ilsd_database(char *ip, char *mac, long long ts){

    sqlite3_stmt *update_ilsd_table_stmt;
    int sqlite3_rc;
    int snprintf_ret;

    char sqlite3_update_string[200];

    /* Fill in SQL command  */
    snprintf_ret = snprintf(
        sqlite3_update_string,
        sizeof(sqlite3_update_string),
        "INSERT OR REPLACE INTO ilsd (ip, mac, ts) VALUES ('%s', '%s', %lld)",
        ip,
        mac,
        ts
    );
    if (snprintf_ret == -1){
        log_message(LOG_CRIT, "sqlite UPDATE statement snprintf failed: %s",
            strerror(errno));
        exit(1);
    }
    if ((int)sizeof(sqlite3_update_string) <= snprintf_ret) {
        log_message(LOG_CRIT,
            "SQLite UPDATE statement was truncated, exiting");
        exit(1);
    }

    /* Prepare statement */
    sqlite3_rc = sqlite3_prepare_v2(
        db,
        sqlite3_update_string,
        -1,
        &update_ilsd_table_stmt,
        NULL
    );
    if(sqlite3_rc != SQLITE_OK){
        log_message(LOG_CRIT,
            "can't prepare ilsd update: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    /* Perform the update */
    sqlite3_rc = sqlite3_step(update_ilsd_table_stmt);
    if(sqlite3_rc != SQLITE_DONE){
        log_message(LOG_CRIT,
            "can't update ilsd table: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    /* Cleanup */
    sqlite3_rc = sqlite3_finalize(update_ilsd_table_stmt);
    if(sqlite3_rc != SQLITE_OK){
        log_message(LOG_CRIT,
            "can't finalize ilsd update: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    return 0;
}

/*
 * Parse and verify a recived ARP packet.
 * Information from an ARP request is written to the database.
 */
void
process_arp_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    /* The sender IP of a recieved ARP request */
    struct in_addr sender_ip;
    /* The sender IP network of a recieved ARP request */
    struct in_addr sender_ip_network;

    /* used to verify return value of snprintf */
    int snprintf_ret;

    /* sender MAC address such as "aa:bb:cc:dd:ee:ff" plus null */
    char sender_mac_string[18];
    /* sender ip address such as "192.168.100.100" plus null */
    char sender_ip_string[16];

    /* Make sure we are not missing packet contents */
    if (CAPTURE_SIZE < header->len){
        log_message(
            LOG_CRIT,
            "Packet length on wire (%lld) is more than expected (%d)",
            (long long)header->len,
            CAPTURE_SIZE
        );
        exit(1);
    }

    /* Make it possible to extract ethernet data from recieved packet */
    ethernet = (struct ethernet_header*)(packet);

    /* Make sure we are dealing with an ARP packet */
    if (ntohs(ethernet->ether_type) != ETHERTYPE_ARP){
        log_message(
            LOG_CRIT,
            "EtherType of recived packet (0x%04x) does not match "
            "expected ARP EtherType (0x%04x)",
            ntohs(ethernet->ether_type),
            ETHERTYPE_ARP
        );
        exit(1);
    }

    /* Make it possible to extract ARP data from recieved packet */
    arp = (struct arp_packet*)(packet + SIZE_ETHERNET);

    /* We only care about ARP requests */
    if (ntohs(arp->opcode) == ARPOP_REQUEST){

        /* Store MAC address as a string for easy access */
        snprintf_ret = snprintf(
            sender_mac_string,
            sizeof(sender_mac_string),
            "%02x:%02x:%02x:%02x:%02x:%02x",
            arp->sender_hw_address[0],
            arp->sender_hw_address[1],
            arp->sender_hw_address[2],
            arp->sender_hw_address[3],
            arp->sender_hw_address[4],
            arp->sender_hw_address[5]
        );
        if (snprintf_ret == -1){
            log_message(LOG_CRIT, "MAC snprintf failed: %s", strerror(errno));
            exit(1);
        }
        if ((int)sizeof(sender_mac_string) <= snprintf_ret) {
            log_message(LOG_CRIT, "MAC address was truncated, exiting");
            exit(1);
        }

        /* Store IP address as a string for easy access */
        snprintf_ret = snprintf(
            sender_ip_string,
            sizeof(sender_ip_string),
            "%d.%d.%d.%d",
            arp->sender_protocol_address[0],
            arp->sender_protocol_address[1],
            arp->sender_protocol_address[2],
            arp->sender_protocol_address[3]
        );
        if (snprintf_ret == -1){
            log_message(LOG_CRIT, "IP snprintf failed: %s", strerror(errno));
            exit(1);
        }
        if ((int)sizeof(sender_ip_string) <= snprintf_ret) {
            log_message(LOG_CRIT, "MAC address was truncated, exiting");
            exit(1);
        }

        /*
         * If our listening interface has a network address only care about IP
         * addresses in that subnet.
         */
        if (netmask.s_addr) {
            /*
             * Convert sender_ip_string to in_addr struct so we can compare
             * addresses
             */
            if (! inet_aton(sender_ip_string, &sender_ip)){
                log_message(LOG_CRIT, "unable to parse sender_ip_string");
                exit(1);
            }

            /*
             * Bitwise AND sender IP address with our netmask to get a network
             * number.
             */
            sender_ip_network.s_addr = sender_ip.s_addr & netmask.s_addr;

            /*
             * The network number of the sender should match our own network
             * number otherwise something strange is going on (misconfigured
             * machine trying to access the network?)
             */
            if (sender_ip_network.s_addr != network.s_addr){
                log_message(
                    LOG_CRIT,
                    "ignoring ARP request from client with ip %s and mac %s",
                    "outside interface subnet",
                    sender_ip_string,
                    sender_mac_string
                );
                return;
            }
        }

        log_message(LOG_INFO, "%lld: ip %s at mac %s",
            (long long)header->ts.tv_sec,
            sender_ip_string,
            sender_mac_string);

        /* Write information to database */
        update_ilsd_database(
            sender_ip_string,
            sender_mac_string,
            (long long)header->ts.tv_sec
        );
    }
}

int
main(int argc, char *argv[])
{

    char *interface;               /* The interface to listen on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    char filter_exp[] = "arp";     /* The filter expression */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */

    int loop_ret;
    int ch, rc;

    debug = 0;
    interface = NULL;

    while ((ch = getopt(argc, argv, "di:")) != -1) {
        switch (ch) {
        case 'd':
            debug = 1;
            break;
        case 'i':
            interface = optarg;
            break;
        default:
            usage();
        }
    }

    if (geteuid()){
        fprintf(stderr, "you need root privileges to run this program\n");
        exit(1);
    }

    if (getpwnam(ILSD_USER) == NULL){
        fprintf(stderr, "you are missing the ilsd user %s", ILSD_USER);
        exit(1);
    }

    init_syslog();

    /* Daemonize */
    if (!debug) {
        daemon(0, 0);
    }

    /* Define the interface */
    if (! interface){
        interface = pcap_lookupdev(errbuf);
        if (interface == NULL) {
            log_message(LOG_CRIT, "Couldn't find default interface: %s", errbuf);
            return(2);
        }
        log_message(LOG_INFO,
            "no interface specified, defaulting to %s",
            interface);
    }
    /* Find the properties for the interface */
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        log_message(LOG_WARNING, "Couldn't get netmask for interface %s: %s",
            interface, errbuf);
        net = 0;
        mask = 0;
    }
    network.s_addr = net;
    netmask.s_addr = mask;

    /*
     * Open the session, no need for promiscuous mode since we are only looking
     * for broadcast arp requests
     */
    pcap_handle = pcap_open_live(interface, CAPTURE_SIZE, 0, 1000, errbuf);
    if (pcap_handle == NULL) {
        log_message(LOG_CRIT,
            "Couldn't open interface %s: %s", interface, errbuf);
        return(2);
    }

    /* Now that we have an open handle we can drop privileges */
    chroot_and_drop_privileges(ILSD_USER);

    /* Compile and apply the filter */
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
        log_message(LOG_CRIT, "Couldn't parse filter %s: %s",
            filter_exp, pcap_geterr(pcap_handle));
        return(2);
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        log_message(LOG_CRIT, "Couldn't install filter %s: %s",
            filter_exp, pcap_geterr(pcap_handle));
        return(2);
    }


    rc = open_ilsd_database();

    if (rc) {
        log_message(LOG_CRIT, "unable to open database, exiting");
        exit(1);
    }

    /* Set up signal handler that breaks the pcap_loop() */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /*
     * Limit what the program is allowed to do. The wpath/cpath permissions are
     * required for the sqlite journal file.
     */
    if (pledge("stdio flock rpath wpath cpath", NULL) == -1){
        log_message(LOG_CRIT, "pledge() failed, exiting");
        exit(1);
    }

    /* Loop until signal is recieved */
    loop_ret = pcap_loop(pcap_handle, -1, process_arp_packet, NULL);

    if (loop_ret == -2) {
        log_message(LOG_WARNING, "pcap loop stopped by signal, exiting");
    } else {
        log_message(LOG_CRIT, "pcap loop stopped unexpectedly: %s (%d)",
            pcap_geterr(pcap_handle), loop_ret);
    }

    /* Close the session */
    pcap_close(pcap_handle);

    rc = close_ilsd_database();
    return(0);
}
