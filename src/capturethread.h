#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread> // 线程解决多设备采集问题
#include <QMutex> // 信号量pause解决线程死循环停止、继续。终止变量break处理跳出问题：终止变量置为1，等待执行结束

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
        this->pause = new QMutex( QMutex::Recursive); // 可以多次封锁
    }
    ~CaptureThread();

    void lock(){
        this->pause->lock();
    }
    void unlock(){
        this->pause->unlock();
    }
    void breakloop(){
        isBreak = true;
    }
protected:
     void run();
     // bool isLocked();

private:
     Nic* nic;
     QMutex* pause;
     bool isBreak;
signals:
     void captured(Pkt* packet);
};

#endif // CAPTURETHREAD_H
