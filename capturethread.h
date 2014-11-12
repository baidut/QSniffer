#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>

class Nic;

class CaptureThread : public QThread {
    Q_OBJECT
public:
    explicit CaptureThread(QObject *parent = 0);
protected:
     void run();
private:
     Nic* nic;
};

#endif // CAPTURETHREAD_H
