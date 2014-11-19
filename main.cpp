#include "mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QTextStream>
#include <QMutex>
#include <QDateTime>
#include <QMessageBox>

/* 竞争力 wireshark 开源但基于C 效率高，但是C++开发效率更高，Qt很友好，简单，有效，重在应用
 * 不处理复杂的信息，只进行应用相关的处理
 */

void outputMessage(QtMsgType type, const QMessageLogContext &context, const QString &msg);

QFile* logFile; // logFile->close();

int main(int argc, char *argv[])
{
#ifdef QS_LOG
    qInstallMessageHandler(outputMessage);//注册MessageHandler
    logFile = new QFile("log.txt");
    bool ret = logFile->open(QIODevice::WriteOnly | QIODevice::Append);
    Q_ASSERT(ret == true);

    QTextStream log(logFile);
    log << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz, ") << "System Start.\r\n";
    logFile->flush();
#endif
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}

/* triggered by:
 *  qWarning("This is a warning message");
 *  qCritical("This is a critical message");
 *  qFatal("This is a fatal message");
 * Notice:
 *  qFatal will triggered a runtime error.
 */

void outputMessage(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    static QMutex mutex;

    mutex.lock();

    QString text;
    switch(type){
        case QtDebugMsg:    text = QString("Debug:\t"); break;
        case QtWarningMsg:  text = QString("Warning:\t");break;
        case QtCriticalMsg: text = QString("Critical:\t"); break;
        case QtFatalMsg:    text = QString("Fatal:\t");
        default:            text = QString("UnknowType:\t");break;
    }

    QString info = QString("File:%1 Line:%2").arg(QString(context.file)).arg(context.line);
    QString curTime = QTime::currentTime().toString("hh:mm:ss.zzz");
    QString logString = QString("%1 %2 %3 %4").arg(curTime).arg(text).arg(msg).arg(info);

    QTextStream log(logFile);
    log << logString << "\r\n";
    logFile->flush();

    mutex.unlock();
}
