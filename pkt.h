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

#include <QString>

/* 封装对一个数据包的解析方法
 * 直解析有用的数据
 */
class Pkt {

public:
    Pkt(struct pcap_pkthdr *header,u_char *pkt_data,Nic* nic){
        this-> header = header;
        this-> pkt_data = pkt_data;
        this-> nic = nic;
    }
    QString getTime();
    int     getLen()    { return header->len;}
    int     getCaplen() { return header->caplen;}
    QString getSrcMac() { return srcMac;}
    QString getDstMac() { return dstMac;}
    QString getType()   { return type;}
    QString getSrcIp()  { return srcIp;}
    QString getDstIp()  { return dstIp;}
    u_short getSrcPort(){ return sport;}
    u_short getDstPort(){ return dport;}
    QString getProto()  { return ip_proto;}
    u_int   getQqNum()  { return qqNumber;}

    void unpackEthHeader();
    void unpackIpHeader();
    void unpackUdpHeader();

    bool parseQq();

    // QQ数据包采用继承的方式，如果检测到包为QQ数据包，则根据父类构建子类。
    // u_char* data() { return pkt_data;} 暴露数据指针不安全

private: // 数据保护

    QString srcMac;
    QString dstMac;
    QString type;
    QString srcIp;
    QString dstIp;
    QString ip_proto;
    u_int   ip_len;
    u_short sport,dport;
    u_int   qqNumber;

    Nic*    nic; // 可以访问数据包来源的网卡设备
    struct  pcap_pkthdr *header; // 头部有时间戳、捕捉长度和原始长度参数（当限制捕捉长度时两者不同）
    u_char* pkt_data;
};

#endif // PKT_H
