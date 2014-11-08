#ifndef NIC_H
#define NIC_H

#include <pcap.h> // 底层数据结构

/* 封装pcap对网络适配器的操作
 * 相当于网卡驱动,对外部隐藏了winpcap
 * 为了提高可移植性，建议不用Qt的数据结构
 */
class Nic{
public:
    Nic(pcap_if_t* dev){
        this-> dev = dev;
    }
    ~Nic();

    bool    open();
    bool    close();
    void    startCaptue();
    int     getStatus();
    int     setMode(int newMode); // onchange : nic-> setMode(XXX)

    bool sendPackage(u_char *content);
    bool setFilter(char* filter, int optimize);

private:
    char*   name;
    char*   description;
    char*   mac_address;
    int     mode;
    int     max_length;
    int     max_timeout;
    char    errbuf[PCAP_ERRBUF_SIZE+1];
    //QStringList addresses;

    pcap_if_t*      dev; // 设备指针
    pcap_t*         adhandle; // 设备操作句柄
    pcap_handler    packet_handler; // 包接收触发函数

    struct bpf_program fcode;
};


#endif // NIC_H
