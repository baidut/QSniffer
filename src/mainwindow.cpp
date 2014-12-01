#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qsniffer.h" //隐藏内部结构，只做类的声明
#include <QMessageBox>
#include <QString>
#include <QCompleter>

#include "pkt.h"


// 主窗口只能打开一个实例的话，可以将qs放在外部，这样可以隐藏qs，但显然不合适
/*
QStringList dev_list = qs.getDeviceList();
ui->comboBox_dev->addItems(dev_list);
int i = ui->comboBox_dev->currentIndex();
Nic dev = qs.getDevice(i);
dev.open();
dev.setFilter("tcp");
dev.startCaptue();
*/

// 仅声明不行class CaptureThread;  invalid use of incomplete type struct 或者是class的解决办法 http://blog.csdn.net/fangyuanseu/article/details/18090149
// error: invalid use of incomplete type 'class CaptureThread'
#include "capturethread.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->qs = new QSniffer(this);
    QStringList dev_list = this->qs->getDeviceList();
    ui->listWidget_dev->addItems(dev_list);


    QStringList strings;
    strings << "tcp" << "tcp and udp" << "udp";
    QCompleter* completer = new QCompleter(strings, this); // 传递this父对象指针，MW析构时可以自动释放
    ui->comboBox_filter->clear();
    ui->comboBox_filter->addItems(strings);
    ui->comboBox_filter->setEditable(true);
    ui->comboBox_filter->setCompleter(completer);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_package_captured(Pkt* pkt){
    QString time,length,source,destination,type,info;

    time = pkt->getTime();
    length = QString("%1/%2").arg(pkt->getLen()).arg(pkt->getCaplen());

    source = pkt->getSrcMac().toQString();
    destination = pkt->getDstMac().toQString();
    if( (pkt->getDstMac()) == (mac_address){0xff,0xff,0xff,0xff,0xff,0xff}){
        destination = "Broadcast";
    }
    switch(pkt->getType()){
        case Pkt::IPV4:
            type = "IPV4";
            source = pkt->getSrcIp().toQString();
            destination = pkt->getDstIp().toQString();
            switch(pkt->getIpProto()){
                case Pkt::UDP:
                    type += ":UDP";
                    source.append(QString(":%1").arg(pkt->getSrcPort()));
                    destination.append(QString(":%1").arg(pkt->getDstPort()));
                    break;
                case Pkt::TCP:
                    type += ":TCP";
                    source.append(QString(":%1").arg(pkt->getSrcPort()));
                    destination.append(QString(":%1").arg(pkt->getDstPort()));
                    break;
                default:
                    break;
            }
            break;
       case Pkt::ARP:
            type = "ARP";
            info = pkt->parseArp();
            break;
       default:
            type = QString("Unkown:0x%1").arg(pkt->getType(),4,16,QChar('0'));//TODO注意这里需要倒序，大小端对齐问题
            break;
    }
    delete pkt;// 释放内存

    int row = ui->tableWidget_pkt->rowCount();
    ui->tableWidget_pkt->insertRow(row);
    ui->tableWidget_pkt->setItem(row,0,new QTableWidgetItem(time));
    ui->tableWidget_pkt->setItem(row,1,new QTableWidgetItem(source));
    ui->tableWidget_pkt->setItem(row,2,new QTableWidgetItem(destination));
    ui->tableWidget_pkt->setItem(row,3,new QTableWidgetItem(type));
    ui->tableWidget_pkt->setItem(row,4,new QTableWidgetItem(length));
    ui->tableWidget_pkt->setItem(row,5,new QTableWidgetItem(info));
    ui->tableWidget_pkt->resizeColumnsToContents();
}

void MainWindow::dumpQqInfo(Pkt* pkt){
    QString source,destination,qqNumber,version,command;
    if(pkt->isAboutQq()){
        qqNumber = QString::number(pkt->getOicqNum());
        //qqNumber = QString("0x%1").arg(pkt->getOicqNum(),0,16);
        source = pkt->getSrcIp().toQString();
        destination = pkt->getDstIp().toQString();
        version = QString("0x%1").arg(pkt->getOicqVersion(),4,16,QChar('0'));
        switch(pkt->getOicqCommand()){
        case 0x0002 : command = QString("Heart Message");break;
        case 0x0058 : command = QString("Download group friend");break;
        case 0x0081 : command = QString("Get status of friend");break;
        case 0x001d : command = QString("Request KEY");break;
        case 0x0017 : command = QString("Receive message");break;
        case 0x0027 : command = QString("Get friend online");break;
        default: command = QString("0x%1")
                 .arg(pkt->getOicqCommand(),4,16,QChar('0'));break;
        }

        int row = ui->tableWidget_pkt->rowCount();
        ui->tableWidget_qq->insertRow(row);
        ui->tableWidget_qq->setItem(row,0,new QTableWidgetItem(qqNumber));
        ui->tableWidget_qq->setItem(row,1,new QTableWidgetItem(command));
        ui->tableWidget_qq->setItem(row,2,new QTableWidgetItem(version));
        ui->tableWidget_qq->setItem(row,3,new QTableWidgetItem(source));
        ui->tableWidget_qq->setItem(row,4,new QTableWidgetItem(destination));
        ui->tableWidget_qq->resizeColumnsToContents();
    }
    delete pkt;
}

void MainWindow::on_pushButton_captureOptions_clicked()
{
    emit shutdown();
}

void MainWindow::on_pushButton_clearFilter_clicked()
{
    ui->comboBox_filter->clear();
    qs->clearFilter();
}

void MainWindow::on_pushButton_applyFilter_clicked()
{
    QString qstr = ui->comboBox_filter->currentText();
    QByteArray ba = qstr.toLatin1();
    char* str = ba.data();
    qs->setFilter(str);
}

void MainWindow::on_pushButton_startCapture_clicked()
{
    ui->tabWidget_main->setCurrentIndex(1);
    int i = 0;
    while( (i = qs->getNextIndex(i)) ){
        CaptureThread* capThread = qs->getCaptureThread(i);
        Q_ASSERT(capThread!=NULL);
        connect(capThread,SIGNAL(captured(Pkt*)),this,SLOT(on_package_captured(Pkt*)),Qt::BlockingQueuedConnection);
    }
    qs->startCapThread();
    ui->actionStopCapture->setEnabled(true);
}

void MainWindow::on_pushButton_sniffQq_clicked()
{
    ui->tabWidget_main->setCurrentIndex(4);
    int i = 0;
    while( (i = qs->getNextIndex(i)) ){
        CaptureThread* capThread = qs->getCaptureThread(i);
        Q_ASSERT(capThread!=NULL);
        connect(capThread,SIGNAL(captured(Pkt*)),this,SLOT(dumpQqInfo(Pkt*)),Qt::BlockingQueuedConnection);
    }
    qs->startCapThread();
    ui->actionStopCapture->setEnabled(true);
}

void MainWindow::on_pushButton_open_clicked()
{
    int i = 0;
    QListWidgetItem* item;
    for(i=0; ( item = ui->listWidget_dev->item(i) );i++){
       if( (item->isSelected()) ){
          qs->grabDevice(i);
       }
    }
    ui->pushButton_close->setEnabled(true);
    ui->pushButton_open->setEnabled(false);
    ui->groupBox_application->setEnabled(true);
    ui->listWidget_dev->setEnabled(false);
}

void MainWindow::on_pushButton_close_clicked()
{
    int i = 0;
    QListWidgetItem* item;
    for(i=0; ( item = ui->listWidget_dev->item(i) );i++){
       if( (item->isSelected()) ){
          qs->releaseDevice(i);
       }
    }
    ui->pushButton_close->setEnabled(false);
    ui->pushButton_open->setEnabled(true);
    ui->groupBox_application->setEnabled(false);
    ui->listWidget_dev->setEnabled(true);
}

void MainWindow::on_actionStartCapture_triggered()
{
    qs->startCapThread();
    ui->actionStartCapture->setEnabled(false);
    ui->actionStopCapture->setEnabled(true);
}

void MainWindow::on_actionStopCapture_triggered()
{
    qs->stopCapThread();
    ui->actionStartCapture->setEnabled(true);
    ui->actionStopCapture->setEnabled(false);
}
