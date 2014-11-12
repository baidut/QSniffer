#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>

class Nic;
class Pkt;
class Packet;

class Packet{
public:
    Packet(int data){
        this->data = data;
    }
    int data;
};

class CaptureThread : public QThread {
    Q_OBJECT
public:
    // explicit CaptureThread(QObject *parent = 0);
    /*explicit CaptureThread(int id,QObject *parent = 0): QThread(parent){
        this->id = id;
    }*/
    CaptureThread(int id){
        this->id = id;
    }

protected:
     void run();
private:
     Nic* nic;
     int id;

signals:
     void captured(int id,Packet* packet);
};

#endif // CAPTURETHREAD_H
