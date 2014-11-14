
#include "pkt.h"
#include <QByteArray>

// Mac头部（14字节）
typedef struct {
    u_char  destination[6];
    u_char  source[6];
    u_short type; //u_short（2字节）
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

void Pkt::unpackEthHeader(){
    ethernet_header* eth = (ethernet_header *)(pkt_data);
    QByteArray dMac, sMac;

    dMac.setRawData((const char *)eth->destination, 6);
    sMac.setRawData((const char *)eth->source, 6);
    dMac = dMac.toHex().toUpper();
    sMac = sMac.toHex().toUpper();

    /*乱码this->srcMac = sMac[0] + sMac[1];
    this->dstMac = dMac[0] + dMac[1];

    for(int i=3;i<12;i+=2){
        this->srcMac +=  sMac[i] + sMac[i+1];
        this->dstMac +=  dMac[i] + dMac[i+1];
    }*/
    this->srcMac = dMac;
    this->dstMac = sMac; // TODO: 每隔两位插入一个：

    switch(eth->type){
    //0x 00 08 for 0x 08 00
    //0x dd 86 for 0x 86 DD
    // 字节大端对齐问题
        case 0x0008:this->type = "IPv4"; break;
        case 0x0608:this->type = "ARP"; break;
        case 0xDD86:this->type = "IPv6"; break;
    default: this->type = QString::number(eth->type,16);break; // "Unkown"
    }
}
