
#include "qsniffer.h"
#include "nic.h"

QSniffer::QSniffer(){
    this-> dev_list = new QStringList;
    /* 获取本机网络设备列表 */
    pcap_if_t* d;

    if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) != -1){
    // 问题1：不兼容，为remote-ext.h中函数 问题2：errbuf warning: deprecated conversion from string constant to 'char*' [-Wwrite-strings]
        /* 初始化网络设备列表，已提供用户选择 */
        // int i = 0;
        for(d=alldevs; d; d=d->next){
            *(this-> dev_list) << ( d->name );
            nic_list.append(NULL);//nic_list[i] = NULL;i++;
        }
        // dev_list == NULL :No interfaces found! Make sure WinPcap is installed.
    }
    //return nullptr;//fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
}

QSniffer::~QSniffer(){
    pcap_freealldevs(this-> alldevs);
}

Nic* QSniffer::getDevice(int index){
    if(nic_list[index]) return nic_list[index];
    pcap_if_t *d;
    int i;
    for(d=alldevs, i=0; i< index-1 ;d=d->next, i++);
    Nic* nic = new Nic(d);
    return nic;
}

bool QSniffer::grabDevice(int index){
    // 需添加检查设备是否已经激活
    if( this->nic_list[index] ) return false;
    pcap_if_t *d=alldevs;
    int i = 0;
    for(;i< index-1;d=d->next, i++);
    Nic* nic = new Nic(d);
    if(nic == NULL) return false;
    this->nic_list[index] = nic;
    return true;
}

bool QSniffer::releaseDevice(int index){
    // 需添加检查设备是否已经删除
    Nic* nic = this->nic_list[index];
    if(NULL == nic )return false;
    delete nic;
    this->nic_list[index] = NULL;
    return true;
}

// 多网卡操作
void QSniffer::startCapture(){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> startCapture();
    }
}
void QSniffer::stopCapture(){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> stopCapture();
    }
}
void QSniffer::setFilter(char* filter, int optimize){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> setFilter( filter, optimize );
    }
}
void QSniffer::setActionOnCaptured(pcap_handler handler_function){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> packet_handler = handler_function;
    }
}
void QSniffer::setActionOnCaptured(pkt_handler handler_function){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> on_captured = handler_function;
    }
}

