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

#ifndef _ILSD_H_
#define _ILSD_H_

/* The user that ilsd drops privileges to */
#define ILSD_USER "_ilsd"

/* Ethernet frame header size (excluding 802.1Q VLAN tag) */
#define SIZE_ETHERNET 14

/*
 *  Expected size of ARP packet captured by tcpdump is 42 bytes when sent from
 *  local machine and 60 bytes when recieved from remote machine (because of
 *  padding added by lower layers of the network stack when sent over the
 *  wire):
 *
 *  Ethernet frame header (14 bytes)
 *  ARP data (28 bytes)
 *  Padding if recieved by remote machine: (18 bytes)
 */
#define CAPTURE_SIZE 60

/* Ethernet and IPv4 constants */
#define ETHER_ADDR_LEN	6
#define IPV4_ADDR_LEN	4

/* Ethernet header */
struct ethernet_header {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_int16_t ether_type;                  /* IP? ARP? RARP? etc */
};

/* Ethertype for the ARP protocol */
#define ETHERTYPE_ARP 0x0806

/* ARP request opcode */
#define ARPOP_REQUEST 1

/* ARP packet */
struct arp_packet {
    u_int16_t hw_address_space;                       /* Hardware address space, like Ethernet) */
    u_int16_t proto_address_space;                    /* Protocol address space, like IP) */
    u_int8_t  hw_byte_length;                         /* Byte length of each hardware (MAC) address */
    u_int8_t  proto_byte_length;                      /* Byte length of each protocol (IP) address */
    u_int16_t opcode;                                 /* opcode, like REQUEST or REPLY */
    u_int8_t  sender_hw_address[ETHER_ADDR_LEN];      /* Hardware address of sender of the packet */
    u_int8_t  sender_protocol_address[IPV4_ADDR_LEN]; /* Protocol address of sender of the packet */
    u_int8_t  target_hw_address[ETHER_ADDR_LEN];      /* Hardware address of target of the packet */
    u_int8_t  target_protocol_address[IPV4_ADDR_LEN]; /* Protocol address of target of the packet */
};

const struct ethernet_header *ethernet; /* The ethernet header */
const struct arp_packet *arp; /* The ARP packet */

void process_arp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void usage(void);

int chroot_and_drop_privileges(char *);

int open_ilsd_database(void);
int close_ilsd_database(void);
int update_ilsd_database(char *, char *, long long);

void init_syslog(void);
void log_message(int, const char *, ...);

void signal_handler(int);

#endif /* _ILSD_H_ */
