#ifndef PKT_H
#define PKT_H

#ifndef WIN32
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <pcap.h>
    #define PCAP_BUF_SIZE 					1024
    #define PCAP_SRC_IF_STRING 				"rpcap://"
    #define PCAP_OPENFLAG_PROMISCUOUS		1
    #define PCAP_SRC_FILE					2
    #define PCAP_OPENFLAG_NOCAPTURE_LOCAL	8
#else
    #include <pcap.h>
    #define WPCAP
    #define HAVE_REMOTE
    #include <remote-ext.h>
#endif

class Nic;

/* 封装对一个数据包的解析方法
 */
class Pkt {
public:
    Pkt(struct pcap_pkthdr *header,u_char *pkt_data,Nic* nic){
        this-> header = header;
        this-> pkt_data = pkt_data;
        this-> nic = nic;
    }
    char*   time();  // 精确到us
    int     len();
    u_char* data();

private:
    Nic*    nic; // 可以访问数据包来源的网卡设备
    struct pcap_pkthdr *header;
    u_char *pkt_data;
};


/* 4 bytes IP address */
typedef struct ip_address
{
    u_char  byte1;
    u_char  byte2;
    u_char  byte3;
    u_char  byte4;
}ip_address;

typedef struct {
    u_char  destination[6];
    u_char  source[6];
    u_short type;
}ethernet_header;

typedef struct {
    u_short hardware_type;
    u_short protocol_type;
    u_char  hardware_size;
    u_char  protocol_size;
    u_char  opcode;
    // padding is part of ethernet frame, not here.
}arp_content;

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

#endif // PKT_H
