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
    this->qs = new QSniffer;
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


void MainWindow::on_pushButton_start_clicked(bool checked)
{
    if(checked){ // started
        ui->pushButton_start->setText("Stop");
        ui->tabWidget_main->setCurrentIndex(1);

        int         i = 0;
        QListWidgetItem* item;
        for(i=0; ( item = ui->listWidget_dev->item(i) );i++){
           if( (item->isSelected()) ){
              qs->grabDevice(i);
              CaptureThread* capThread = qs->getCaptureThread(i);
              Q_ASSERT(capThread!=NULL);
              connect(capThread,SIGNAL(captured(Pkt*)),this,SLOT(on_package_captured(Pkt*)));
           }
        }
        qs->startCapThread();
    }
    else{
        ui->pushButton_start->setText("Start");
        qs->stopCapThread();
    }
}

void MainWindow::on_package_captured(Pkt* pkt){
    QString time,length,source,destination,type,info;

    time = pkt->getTime();
    length = QString("%1/%2").arg(pkt->getLen()).arg(pkt->getCaplen());

    pkt->unpackEthHeader();

    type = pkt->getType();
    if(type=="IPv4"){
        pkt->unpackIpHeader();
        source = pkt->getSrcIp().toQString();
        destination = pkt->getDstIp().toQString();
        type = pkt->getProto();
        if(type == "udp"){
            pkt->unpackUdpHeader();
            source.append(QString(":%1").arg(pkt->getSrcPort()));
            destination.append(QString(":%1").arg(pkt->getDstPort()));

            /*if(pkt->parseQq()){
                int row = ui->tableWidget_pkt->rowCount();
                ui->tableWidget_qq->insertRow(row);
                ui->tableWidget_qq->setItem(row,1,new QTableWidgetItem(pkt->getSrcIp()));
                ui->tableWidget_qq->setItem(row,2,new QTableWidgetItem(pkt->getDstIp()));
                ui->tableWidget_qq->setItem(row,3,new QTableWidgetItem(pkt->getQqNum()));
            }*/
        }
        else if(type == "arp"){
            info = pkt->parseArp();
        }
    }
    else {
        source = pkt->getSrcMac().toQString();
        destination = pkt->getDstMac().toQString();
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
