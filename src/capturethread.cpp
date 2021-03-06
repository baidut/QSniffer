#include "capturethread.h"

#include <QObject>
#include "nic.h"

void CaptureThread::run(){
    Pkt* pkt = NULL;
    while(!QThread::currentThread()->isInterruptionRequested()){
        pkt= nic->getNextPacket();
        if (pkt!=NULL)
            emit captured(pkt); // pkt可以携带设备信息，因此这里不再发送设备指针
    }
    qDebug("CaptureThread finished.");
}
