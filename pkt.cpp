
#include "pkt.h"
#include <QByteArray>
#include <winsock2.h> // ntohs

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
    u_short opcode;
    mac_address senderMac;
    ip_address  senderIp;
    mac_address targetMac;
    ip_address  targetIp;
    // padding is part of ethernet frame, not here.
}arp_content;

// IP协议
/* IPv4 header */
typedef struct ipv4_header
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


// IP 协议头 协议(Protocol) 字段标识含义
//      协议      协议号

#define IP_SIG			(0)
#define ICMP_SIG		(1)
#define IGMP_SIG		(2)
#define GGP_SIG			(3)
#define IP_ENCAP_SIG	(4)
#define ST_SIG			(5)
#define TCP_SIG			(6)
#define EGP_SIG			(8)
#define PUP_SIG			(12)
#define UDP_SIG			(17)
#define HMP_SIG			(20)
#define XNS_IDP_SIG		(22)
#define RDP_SIG			(27)
#define TP4_SIG			(29)
#define XTP_SIG			(36)
#define DDP_SIG			(37)
#define IDPR_CMTP_SIG	(39)
#define RSPF_SIG		(73)
#define VMTP_SIG		(81)
#define OSPFIGP_SIG		(89)
#define IPIP_SIG		(94)
#define ENCAP_SIG		(98)


// TCP 协议
// TCP头部（20字节）
typedef struct _tcp_header {
    u_short	sport;				// 源端口号
    u_short	dport;				// 目的端口号
    u_int	seq_no;				// 序列号
    u_int	ack_no;				// 确认号
    u_char	thl:4;				// tcp头部长度
    u_char	reserved_1:4;		// 保留6位中的4位首部长度
    u_char	reseverd_2:2;		// 保留6位中的2位
    u_char	flag:6;				// 6位标志
    u_short	wnd_size;			// 16位窗口大小
    u_short	chk_sum;			// 16位TCP检验和
    u_short	urgt_p;				// 16为紧急指针
}tcp_header;

#define FTP_PORT 		(21)
#define TELNET_PORT 	(23)
#define SMTP_PORT 		(25)
#define HTTP_PORT  		(80)
#define HTTPS_PORT		(443)
#define HTTP2_PORT 		(8080)
#define POP3_PORT 		(110)


// UDP 协议
/* UDP header*/
typedef struct udp_header {
    u_short sport;			// Source port
    u_short dport;			// Destination port
    u_short len;			// Datagram length
    u_short crc;			// Checksum
}udp_header;

#define DNS_PORT		(53)
#define SNMP_PORT		(161)

#define QQ_SIGN			('\x02')	// OICQ协议标识
#define QQ_SER_PORT		(8000)		// QQ服务器所用端口号
#define QQ_NUM_OFFSET	(7)			// QQ号码信息在QQ协议头中的偏移

QString Pkt::getTime(){
    struct tm *ltime;
    char timestr[10];
    time_t local_tv_sec;
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    // sprintf(timestr,"%s%.6d",timestr,header->ts.tv_usec);
    return QString("%1.%2").arg(timestr).arg(header->ts.tv_usec);
}

QString Pkt::ip2QSting(ip_address addr){
    return QString("%1.%2.%3.%4")
            .arg(addr.byte1)
            .arg(addr.byte2)
            .arg(addr.byte3)
            .arg(addr.byte4);
}

QString Pkt::mac2QSting(mac_address addr){
    // 注意是16进制,占2位
    return QString("%1:%2:%3:%4:%5:%6")
            .arg(addr.byte1,2,16)
            .arg(addr.byte2,2,16)
            .arg(addr.byte3,2,16)
            .arg(addr.byte4,2,16)
            .arg(addr.byte5,2,16)
            .arg(addr.byte6,2,16);
}

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
    this->dstMac = sMac; // TODO: 每隔两位插入一个： 通过结构体实现比较简单

    switch(eth->type){
    //0x 00 08 for 0x 08 00
    //0x dd 86 for 0x 86 DD
    // 字节大端对齐问题
        case 0x0008:this->type = "IPv4"; break;
        case 0x0608:this->type = "ARP"; break;
        case 0xDD86:this->type = "IPv6"; break;
        default: this->type = QString("Unkown:")
                                .append(QString::number(eth->type,16));
                 break;
    }
}

void Pkt::unpackIpHeader(){
    ipv4_header* ih = (ipv4_header *)(pkt_data+sizeof(ethernet_header));
    ip_len = (ih->ver_ihl & 0xF) * 4;
    srcIp = ip2QSting(ih->saddr);
    dstIp = ip2QSting(ih->daddr);
    switch(ih->proto){
        case UDP_SIG: this->ip_proto = "udp"; break;
        case TCP_SIG: this->ip_proto = "tcp"; break;
        default: this->ip_proto = QString("Unkown:").append(QString::number(ih->proto));break;
    }
}

void Pkt::unpackUdpHeader(){
    udp_header* uh = (udp_header *)(pkt_data + sizeof(ethernet_header) + ip_len);
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);
}

QString Pkt::parseArp(){
    arp_content* content = (arp_content *)(pkt_data+sizeof(ethernet_header));
    QString ArpType;

    switch(content->opcode){
    // 大端小端问题
        case 0x0100:
            ArpType = "ARP Request";
            if( content->targetIp == content->senderIp )
               info = QString("%1:who has %2? tell %3")
                        .arg(ArpType)
                        .arg(ip2QSting(content->targetIp))
                        .arg(ip2QSting(content->senderIp));
            else{
               info = QString("%1:Gratuitous ARP for %2")
                        .arg(ArpType)
                        .arg(content->senderIp.toQString());
            }
            break;
        case 0x0200:
            ArpType = "ARP Reply";
            info = QString("%1:%2 is at %3")
                    .arg(ArpType)
                    .arg(ip2QSting(content->senderIp))
                    .arg(mac2QSting(content->senderMac));
            break;
        case 0x0300: ArpType = "RARP Request"; break;
        case 0x0400: ArpType = "RARP Reply"; break;
        default: info = QString("Unkown:")
                        .append(QString::number(content->opcode));
                 break;
    }
    return info;
}

bool Pkt::parseQq(){
    u_char *pByte = pkt_data + sizeof(ethernet_header) + ip_len + sizeof(udp_header);
    if (*pByte == QQ_SIGN && (sport == QQ_SER_PORT || dport == QQ_SER_PORT) ) {
        qqNumber = *(int *)(pByte + QQ_NUM_OFFSET);
    }
    qqNumber = ntohl(qqNumber);// 转换字节序
    if (qqNumber == 0) return false;
    return true;
}
