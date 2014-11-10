#ifndef NIC_H
#define NIC_H

// 底层数据结构
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

/* 封装pcap对网络适配器的操作
 * 相当于网卡驱动,对外部隐藏了winpcap
 * 为了提高可移植性，建议不用Qt的数据结构
 */
class Pkt;

typedef void (*pkt_handler)(Pkt*);

class Nic{
public:
    Nic(pcap_if_t* dev){
        this-> dev = dev;
        max_length = 65536;
        max_timeout = 1000;
        mode = PCAP_OPENFLAG_PROMISCUOUS;
    }
    ~Nic();

    bool    open();
    bool    close();
    void    startCapture();
    void    stopCapture();
    int     getStatus();

    bool    sendPackage(u_char *content);
    bool    setFilter(char* filter, int optimize);

    int     mode;
    int     max_length;
    int     max_timeout;
    pkt_handler  on_captured; // pcap_handler: new Packet, call on_captured function;
    pcap_handler packet_handler; // 包接收触发函数 默认为分发器

private:
    char*   name;
    char*   description;
    char*   mac_address;

    char    errbuf[PCAP_ERRBUF_SIZE+1];
    //QStringList addresses;

    pcap_if_t*      dev; // 设备指针
    pcap_t*         adhandle; // 设备操作句柄

    struct bpf_program fcode;
};


#endif // NIC_H
