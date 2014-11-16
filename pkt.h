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
                .arg(byte1,3,10,QChar(' '))
                .arg(byte2,3,10,QChar(' '))
                .arg(byte3,3,10,QChar(' '))
                .arg(byte4,3,10,QChar(' '));
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
    //0x 00 08 for 0x 08 00
    //0x dd 86 for 0x 86 DD
    // 字节大端对齐问题
    typedef enum{
        IPV6 = 0xDD86,
        ARP = 0x0608,
        IPV4 = 0x0008,
    }ethType;
    typedef enum{
        IP,     ICMP,   IGMP,   GGP,    IP_ENCAP,
        ST,     TCP,
        EGP = 8,
        UDP = 17,
    }ipProto;

    Pkt(struct pcap_pkthdr *header,u_char *pkt_data,Nic* nic){
        this-> header = header;
        this-> pkt_data = pkt_data;
        this-> nic = nic;
    }
    QString getTime();
    int     getLen()    { return header->len;}
    int     getCaplen() { return header->caplen;}
    mac_address getSrcMac();
    mac_address getDstMac();
    u_short     getType();
    ip_address  getSrcIp();
    ip_address  getDstIp();
    u_short getSrcPort();
    int     getIpLen();
    u_short getDstPort();
    u_char  getIpProto();
    u_int   getQqNum()  { return qqNumber;}

    bool    parseQq();
    QString parseArp();

    // QQ数据包采用继承的方式，如果检测到包为QQ数据包，则根据父类构建子类。
    // u_char* data() { return pkt_data;} 暴露数据指针不安全

    QString ip2QSting(ip_address);
    QString mac2QSting(mac_address);

private:
    u_int   qqNumber;
    QString info;

    Nic*    nic; // 可以访问数据包来源的网卡设备
    struct  pcap_pkthdr *header; // 头部有时间戳、捕捉长度和原始长度参数（当限制捕捉长度时两者不同）
    u_char* pkt_data;
};



#endif // PKT_H
