#ifndef QSNIFFER_H
#define QSNIFFER_H

#include "nic.h"
#include <QStringList>

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

// 可以捕捉多个设备,创建多个设备，同时开始捕捉
class QSniffer // 不做设备的驱动，完成更高层的应用，目前还没有什么内容
{
public:
    QSniffer();
    ~QSniffer();
    QStringList& getDeviceList(){
        return *(this-> dev_list);
    }
    Nic& getDevice(int index);
private:
    pcap_if_t*      alldevs;
    QStringList*    dev_list;   // 列表可能为空，改为指针比较好
    QList<Nic*>     active_nic; // 维护需要工作的网卡
    char            errbuf[PCAP_ERRBUF_SIZE+1];
};

#endif // QSNIFFER_H
