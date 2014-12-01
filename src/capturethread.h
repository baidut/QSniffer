#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread> // 线程解决多设备采集问题

class Nic;
class Pkt; // 采集线程不知道数据包的结构和操作，相关处理由Nic进行，它只是将包传送到主窗口

class CaptureThread : public QThread {
    Q_OBJECT
public:
    // explicit CaptureThread(QObject *parent = 0);
    /*explicit CaptureThread(int id,QObject *parent = 0): QThread(parent){
        this->id = id;
    }*/
    CaptureThread(Nic* nic){
        this->nic = nic;
        isBreak = false;
    }
    ~CaptureThread(){
        isBreak = true;
        qDebug("break!");
        this->disconnect();// 注意先要断开连接之后再等待结束，否则会死
        this->wait();
    }
protected:
     void run();
private:
     Nic* nic;
     bool isBreak;
signals:
     void captured(Pkt* packet);
};

#endif // CAPTURETHREAD_H
