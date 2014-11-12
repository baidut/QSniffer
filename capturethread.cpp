#include "capturethread.h"

#include <QObject>

// 测试给主窗口发送数据包


//CaptureThread::CaptureThread(QObject *parent):QThread(parent){
//}

void CaptureThread::run(){
// static int i = 1; 不是一次更新，而相当于另一个主函数

    for (int i = 0; i < 5; i++){
        Packet* pkt = new Packet(i);
        emit captured(id,pkt);
    }
}
