#ifndef QSNIFFER_H
#define QSNIFFER_H

#include "nic.h"
#include <QStringList>
#include <QVector> //  error: field 'nic_list' has incomplete type
#include <QObject>

/* e.g.
 * QSniffer qs = QSniffer();
 * QStringList dev_list = qs.getDeviceList();
 * ui->comboBox_dev->addItems(dev_list);
 * int i = ui->comboBox_dev->currentIndex();
 * Nic dev = qs.getDevice(i);
 * dev.open();
 * dev.setFilter("tcp");
 * dev.startCaptue();
 */


class MainWindow;
class CaptureThread;

// 可以捕捉多个设备,创建多个设备，同时开始捕捉
// 不做设备的驱动，完成更高层的应用，目前还没有什么内容
class QSniffer :public QObject {

    Q_OBJECT

public:
    explicit QSniffer(QObject* parent = 0); ;
    ~QSniffer();

    QStringList& getDeviceList(){
        return *(this-> dev_list);
    }
    // 用于对单个网卡的操作
    Nic *getDevice(int index);
    // 用于配量操作
    bool grabDevice(int index); // 实例化设备类，接收线程
    bool releaseDevice(int index);
    CaptureThread* getCaptureThread(int index);
    void setFilter(char *filter, int optimize);
    void startCapture();
    void stopCapture();
    void startCapThread();  // 全部线程运行
    void stopCapThread(); // 全部线程终止 停止信号的发送 通过信号量实现
    void setActionOnCaptured(pkt_handler handler_function); // 封装后的包处理函数
    void setActionOnCaptured(pcap_handler handler_function); // 也可以不通过分发，直接设置

private:
    QVector<Nic*>   nic_list;   // 为了便于维护，对应各个设备的指针，为空时设备未激活
    QVector<CaptureThread*> capThread_list; // 和nic相同的方式维护 职能：取设备下一个数据包，并发送出去
    // 设备类可改为非QObject，交给线程处理
    pcap_if_t*      alldevs;    // 所有可用的设备列表
    QStringList*    dev_list;   // 列表可能为空，改为指针比较好
    char            errbuf[PCAP_ERRBUF_SIZE+1];
};

#endif // QSNIFFER_H
