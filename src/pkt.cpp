
#include "pkt.h"
#include <QByteArray>
#ifdef WIN32
#include <winsock2.h> // ntohs
#endif
// Mac头部（14字节）
typedef struct {
    mac_address  dstMac;
    mac_address  srcMac;
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
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits) // TODO 可改为位域实现
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

//#undef inline pcap.h中对inline进行了定义，造成这里inline不可用，如果能将pcap.h从本文件分离出去就能解决问题

mac_address Pkt::getSrcMac(){
    return ((ethernet_header *)(pkt_data))->srcMac;
}
mac_address Pkt::getDstMac(){
    return ((ethernet_header *)(pkt_data))->dstMac;
}
u_short Pkt::getType(){
    return ((ethernet_header *)(pkt_data))->type;
}

int Pkt::getIpLen(){ // 0x45 4-IPV4 5-5*4=20
    return 4 * (((ipv4_header *)(pkt_data+sizeof(ethernet_header)))->ver_ihl & 0xF);
}
ip_address Pkt::getSrcIp(){
    return ((ipv4_header *)(pkt_data+sizeof(ethernet_header)))->saddr;
}
ip_address Pkt::getDstIp(){
    return ((ipv4_header *)(pkt_data+sizeof(ethernet_header)))->daddr;
}
u_char Pkt::getIpProto(){
    return ((ipv4_header *)(pkt_data+sizeof(ethernet_header)))->proto;
}

u_short Pkt::getSrcPort(){
    return ntohs(((udp_header *)(pkt_data + sizeof(ethernet_header) + getIpLen() )
                                )->sport);
}
u_short Pkt::getDstPort(){
    return ntohs(((udp_header *)(pkt_data + sizeof(ethernet_header) + getIpLen() )
                                )->dport);
}

QString Pkt::parseArp(){
    arp_content* content = (arp_content *)(pkt_data+sizeof(ethernet_header));
    QString ArpType;
    QString info;

    switch(content->opcode){
    // 大端小端问题
        case 0x0100:
            ArpType = "ARP Request";
            if( content->targetIp == content->senderIp )
               info = QString("%1:Gratuitous ARP for %2")
                         .arg(ArpType)
                         .arg(content->senderIp.toQString());
            else{
               info = QString("%1:who has %2? tell %3")
                        .arg(ArpType)
                        .arg((content->targetIp).toQString())
                        .arg((content->senderIp).toQString());
            }
            break;
        case 0x0200:
            ArpType = "ARP Reply";
            info = QString("%1:%2 is at %3")
                    .arg(ArpType)
                    .arg((content->senderIp).toQString())
                    .arg((content->senderMac).toQString());
            break;
        case 0x0300: ArpType = "RARP Request"; break;
        case 0x0400: ArpType = "RARP Reply"; break;
        default: info =  QString("Unkown:0x%1")
                .arg(content->opcode,4,16,QChar('0'));break;
    }
    return info;
}

#define OICQ_PROTO      (0x02)
#define QQ_SER_PORT		(8000)		// QQ服务器所用端口号

typedef struct oicq_packet{
    //u_char flag; // 这里损失了一个字节做补充，因此长度出错 解决办法：去掉头部
    u_short version;
    u_short command;
    u_short sequence; // 删除了上面的，这里还会补充一个u_short
    u_int   number;// 4 bits
}oicq_packet;
// 按照结构体存放有字节对齐问题造成的字节填充问题
#define VERSION_OFFSET   (1)
#define COMMAND_OFFSET   (3)
#define SEQUENCE_OFFSET  (5)
#define NUMBER_OFFSET    (7)

bool Pkt::isAboutQq(){
    u_char* pByte = pkt_data + sizeof(ethernet_header) + getIpLen() + sizeof(udp_header);

    if( (this->getType() == Pkt::IPV4 )
       && (this->getIpProto()== Pkt::UDP)
          && (*pByte == OICQ_PROTO)
            && (getSrcPort() == QQ_SER_PORT || getDstPort() == QQ_SER_PORT)){
        return true;
    }
    else return false;
}

u_int Pkt::getOicqNum(){
    return ntohl( *(u_int*) ( pkt_data + sizeof(ethernet_header) + getIpLen() + sizeof(udp_header) +NUMBER_OFFSET));
    // IpLen must be 20.
}

u_short Pkt::getOicqCommand(){
    return ntohs( *(u_short*) ( pkt_data + sizeof(ethernet_header) + getIpLen() + sizeof(udp_header) +COMMAND_OFFSET) );
}

u_short Pkt::getOicqVersion(){
    return ntohs( *(u_short*) ( pkt_data + sizeof(ethernet_header) + getIpLen() + sizeof(udp_header) +VERSION_OFFSET) );
}
