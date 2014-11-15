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

typedef struct mac_address{
    u_char  byte1;
    u_char  byte2;
    u_char  byte3;
    u_char  byte4;
    u_char  byte5;
    u_char  byte6;

    QString toQString(){
        return QString("%1:%2:%3:%4:%5:%6")
                .arg(byte1,2,16,QChar('0'))// 注意是16进制,占2位,空位补0
                .arg(byte2,2,16,QChar('0'))
                .arg(byte3,2,16,QChar('0'))
                .arg(byte4,2,16,QChar('0'))
                .arg(byte5,2,16,QChar('0'))
                .arg(byte6,2,16,QChar('0'));
    } // 变换函数更方便
    bool operator == (const struct mac_address& other) const{
           return       (byte1 == other.byte1)
                   &&   (byte2 == other.byte2)
                   &&   (byte3 == other.byte3)
                   &&   (byte4 == other.byte4)
                   &&   (byte5 == other.byte5)
                   &&   (byte6 == other.byte6);
    }
}mac_address;

typedef struct ip_address{
    u_char  byte1;
    u_char  byte2;
    u_char  byte3;
    u_char  byte4;

    QString toQString(){
        return QString("%1.%2.%3.%4")
                .arg(byte1)
                .arg(byte2)
                .arg(byte3)
                .arg(byte4);
    }
    bool operator == (const struct ip_address& other) const{
       return       (byte1 == other.byte1)
               &&   (byte2 == other.byte2)
               &&   (byte3 == other.byte3)
               &&   (byte4 == other.byte4);
    }
}ip_address;

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
    QString getType()   { return type;}
    mac_address getSrcMac() { return srcMac;}
    mac_address getDstMac() { return dstMac;}
    ip_address  getSrcIp()  { return srcIp;}
    ip_address  getDstIp()  { return dstIp;}
    u_short getSrcPort(){ return sport;}
    u_short getDstPort(){ return dport;}
    QString getProto()  { return ip_proto;}
    u_int   getQqNum()  { return qqNumber;}

    void    unpackEthHeader();
    void    unpackIpHeader();
    void    unpackUdpHeader();

    bool    parseQq();
    QString parseArp();

    // QQ数据包采用继承的方式，如果检测到包为QQ数据包，则根据父类构建子类。
    // u_char* data() { return pkt_data;} 暴露数据指针不安全

    QString ip2QSting(ip_address);
    QString mac2QSting(mac_address);

private:

    QString type;
    mac_address srcMac;
    mac_address dstMac;
    ip_address  srcIp;
    ip_address  dstIp;
    QString ip_proto;
    u_int   ip_len;
    u_short sport,dport;
    u_int   qqNumber;
    QString info;

    Nic*    nic; // 可以访问数据包来源的网卡设备
    struct  pcap_pkthdr *header; // 头部有时间戳、捕捉长度和原始长度参数（当限制捕捉长度时两者不同）
    u_char* pkt_data;
};

#endif // PKT_H
