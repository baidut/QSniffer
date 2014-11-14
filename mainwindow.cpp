#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qsniffer.h" //隐藏内部结构，只做类的声明
#include <QMessageBox>
#include <QString>

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
    ui->textBrowser_pkt->append(QString("packet captured:%1").arg(QString((const char*)(pkt->data()))));
    //int row = ui->tableWidget_pkt->rowCount();
    //ui->tableWidget_pkt->insertRow(row);
    //ui->tableWidget_pkt->setItem(row,0,new QTableWidgetItem("Hello!"));
    //ui->tableWidget_pkt->setItem(row,0,new QTableWidgetItem((const char*)pkt->time()));
    //ui->tableWidget_pkt->setItem(row,0,new QTableWidgetItem((const char*)pkt->time()));
    delete pkt;// 否则内存。。。。
}

void MainWindow::on_pushButton_captureOptions_clicked()
{
    emit shutdown();
}
