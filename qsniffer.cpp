
#include "qsniffer.h"

QSniffer::QSniffer(){
    this-> dev_list = new QStringList;
    /* 获取本机网络设备列表 */
    pcap_if_t* d;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1){
        /* 初始化网络设备列表，已提供用户选择 */
        for(d=alldevs; d; d=d->next){
            *(this-> dev_list) << ( d->name );
        }
        // dev_list == NULL :No interfaces found! Make sure WinPcap is installed.
    }
    //return nullptr;//fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
}

Nic& QSniffer::getDevice(int index){
pcap_if_t *d;
int i;
    for(d=alldevs, i=0; i< index-1 ;d=d->next, i++);
    Nic* nic = new Nic(d);
    return *nic;
}

QSniffer::~QSniffer(){
    pcap_freealldevs(this-> alldevs);
}
