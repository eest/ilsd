This is the IP-last-seen deamon, or ilsd for short.

The goal is to build a database of when a given IP address was last being used
on the network.

This is done by listening for ARP request packets and recording the sender IP
and MAC together with a timestamp in a SQLite database.

The program has only been tested on OpenBSD and depends on the OpenBSD pledge()
system call to restrict what it is allowed to do.

It requires a user called "_ilsd" which can be created in this way:
```
# useradd -d /var/ilsd -s /sbin/nologin -c "IP last seen daemon" _ilsd
# install -d -m 0755 -o root -g wheel /var/ilsd
# install -d -m 0775 -o root -g _ilsd /var/ilsd/db
```

The code is heavily influenced by a bunch of external resources:
* Packet parsing: Programming with pcap, http://www.tcpdump.org/pcap.html
* ARP packet format: OpenBSD network stack,
    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/net/if_arp.h,
    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/netinet/if_ether.h
* chroot/privdrop/logging/pledge: OpenBGPD, http://www.openbgpd.org/

All shortcomings in the code are my own.
