
#include "qsniffer.h"
#include "nic.h"
#include "capturethread.h"

QSniffer::QSniffer(QObject* parent): QObject(parent){
    this-> dev_list = new QStringList;
    /* 获取本机网络设备列表 */
    pcap_if_t* d;

    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        sprintf(errbuf,"Error in pcap_findalldevs: %s\n",errbuf);
        return;
    }
    for(d=alldevs; d; d=d->next){
        *(this-> dev_list) << ( d->name );
        nic_list.append(NULL);//nic_list[i] = NULL;i++;
        capThread_list.append(NULL);
    }
    if(d==alldevs){
        sprintf(errbuf,"No interfaces found! Make sure WinPcap is installed");
        return; // 使用设备时触发错误，返回出错信息
    }
}

QSniffer::~QSniffer(){
    pcap_freealldevs(this-> alldevs);
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        this->releaseDevice(i);
    }
}

void QSniffer::startCapThread(){
    for(int i = 0; i< capThread_list.size(); i++)if(capThread_list[i]){
        capThread_list[i]->start();
    }
}

void QSniffer::stopCapThread(){
    for(int i = 0; i< capThread_list.size(); i++)if(capThread_list[i]){
        delete capThread_list[i];
    }
}

Nic* QSniffer::getDevice(int index){
    if(nic_list[index]) return nic_list[index];
    else return NULL; // 没有创建则返回空，并不执行创建
}

CaptureThread* QSniffer::getCaptureThread(int index){
    if(capThread_list[index]) return capThread_list[index];
    else return NULL; // 没有创建则返回空
}

bool QSniffer::grabDevice(int index){
    // 设备已经激活
    if( this->nic_list[index] ) return false;
    pcap_if_t *d=alldevs;
    int i = 0;
    for(;i< index-1;d=d->next, i++);
    Nic* nic = new Nic(d);
    // 设备创建失败
    Q_ASSERT(nic != NULL);
    this->nic_list[index] = nic;
    // 创建接收线程
    CaptureThread* capThread = new CaptureThread(nic);
    Q_ASSERT(capThread != NULL);
    this->capThread_list[index]=capThread;
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

