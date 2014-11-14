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

/* 封装对一个数据包的解析方法 解析的数据如何传递-QString还是普通的char*
 * QString可以自行释放，而且可变长
 * 如果是char*还需要释放数据，在包析构的时候进行处理
 */
class Pkt {
    /* 类内部typedef
        typedef enum{
            IPv4 = 0x0800,
            ARP = 0x0806,
            IPv6 = 0x86DD,
        }QEthType;
        typedef struct{
            QString    dst;
            QString    src;
            QEthType   type;
        }QEthHeader;*/
public:
    Pkt(struct pcap_pkthdr *header,u_char *pkt_data,Nic* nic){
        this-> header = header;
        this-> pkt_data = pkt_data;
        this-> nic = nic;
    }
    // header 解析
    QString time(){
        struct tm *ltime;
        char timestr[10];
        time_t local_tv_sec;
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        // sprintf(timestr,"%s%.6d",timestr,header->ts.tv_usec);
        return QString("%1.%2").arg(timestr).arg(header->ts.tv_usec);
    }
    int len(){
        return header->len;
    }
    int caplen(){
        return header->caplen;
    }
    // 数据解析
    u_char* data(){
        return pkt_data;
    }
    // QEthHeader unpackEthHeader();

private:
    Nic*    nic; // 可以访问数据包来源的网卡设备
    struct pcap_pkthdr *header; // 头部有时间戳、捕捉长度和原始长度参数（当限制捕捉长度时两者不同）
    u_char *pkt_data;
};

#endif // PKT_H
