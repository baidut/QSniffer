
#include "pkt.h"
#include <QByteArray>

// Mac头部（14字节）
typedef struct {
    u_char  destination[6];
    u_char  source[6];
    u_short type;
}ethernet_header;

// ARP协议
typedef struct {
    u_short hardware_type;
    u_short protocol_type;
    u_char  hardware_size;
    u_char  protocol_size;
    u_char  opcode;
    // padding is part of ethernet frame, not here.
}arp_content;
/* 4 bytes IP address */
typedef struct ip_address
{
    u_char  byte1;
    u_char  byte2;
    u_char  byte3;
    u_char  byte4;
}ip_address;
/* IPv4 header */
typedef struct ip_header
{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service
    u_short tlen;			// Total length
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    ip_address	saddr;		// Source address
    ip_address	daddr;		// Destination address
    u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
    u_short sport;			// Source port
    u_short dport;			// Destination port
    u_short len;			// Datagram length
    u_short crc;			// Checksum
}udp_header;

/*Pkt::QEthHeader Pkt::unpackEthHeader(){
    ethernet_header* eth = (ethernet_header *)(pkt_data);
    QByteArray dMac, sMac;

    dMac.setRawData((const char *)eth->destination, 6);
    sMac.setRawData((const char *)eth->source, 6);
    dMac = dMac.toHex().toUpper();
    sMac = sMac.toHex().toUpper();

    for(int i=0;i<12;i+=2){
        dMac.insert(i,':');
        sMac.insert(i,':');
    }
    QEthHeader hdr = {
        QString(dMac),
        QString(sMac),
        (QEthType)eth->type,
    };
    return hdr;//QEthHeader(QString(dMac),QString(sMac),(QEthType)eth->type);
}*/

