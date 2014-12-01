
#include "qsniffer.h"
#include "nic.h"
#include "capturethread.h"

QSniffer::QSniffer(QObject* parent): QObject(parent){
    this-> dev_list = new QStringList;
    /* 获取本机网络设备列表 */
    pcap_if_t* d;
    QString dev_info;

    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        sprintf(errbuf,"Error in pcap_findalldevs: %s\n",errbuf);
        return;
    }
    for(d=alldevs; d; d=d->next){
        dev_info = QString("%1[%2]").arg(d->name).arg((d->description)?(d->description):"No description available");
        *(this-> dev_list) << dev_info;
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
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        if(capThread_list[i]==NULL){
            capThread_list[i]= new CaptureThread(nic_list[i]);
            qDebug("new capThread");
            // 需要重连信号
            if(this->parent())
                connect(capThread_list[i],SIGNAL(captured(Pkt*)),
                        this->parent(),SLOT(on_package_captured(Pkt*)),
                        Qt::BlockingQueuedConnection);
            qDebug("connect compeleted.");
        }
        Q_ASSERT(capThread_list[i] != NULL);
        capThread_list[i]->start();
    }
}

void QSniffer::stopCapThread(){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        capThread_list[i]->breakLoop();
        while(!capThread_list[i]->isFinished());
        delete (capThread_list[i]);
        capThread_list[i] = NULL;
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
    for(;i< index;d=d->next, i++); // 差1bug
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
void QSniffer::setFilter(char* filter, int optimize){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> setFilter( filter, optimize );
    }
}
void QSniffer::clearFilter(){
    for(int i = 0; i< nic_list.size(); i++)if(nic_list[i]){
        nic_list[i]-> setFilter("");
    }
}

// 这是个比较烂的方法，根据当前索引返回下一个，如果没有则返回0，暂时先这么实现，之后再修改
int QSniffer::getNextIndex(int index){
    if(index<0)return 0;
    for(int i = index+1; i< nic_list.size(); i++)if(nic_list[i]){
        return i;
    }
    return 0;
}

