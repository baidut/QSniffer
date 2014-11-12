#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qsniffer.h" //隐藏内部结构，只做类的声明
#include <QMessageBox>
#include <QString>


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

    CaptureThread* cap = new CaptureThread(1); // ,(QObject*)this
    connect(cap,SIGNAL(captured(int,Packet*)),this,SLOT(on_package_captured(int,Packet*)));
    cap->start();

    /*this->qs = new QSniffer;
    QStringList dev_list = this->qs->getDeviceList();
    ui->listWidget_dev->addItems(dev_list);*/
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
              if(qs->getDevice(i))
                connect( qs->getDevice(i),SIGNAL(captured(Pkt*)),this,SLOT(on_package_captured(Pkt*)));
           }
        }
        QMessageBox::information(NULL, "Title",  "hahha" , QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);

        qs->startCapture();
    }
    else{
        ui->pushButton_start->setText("Start");
        qs->stopCapture();
    }
}

void MainWindow::on_package_captured(Pkt* pkt){
    //sprintf
    ui->textBrowser_pkt->append("packet captured!");
    // delete pkt;// 否则内存。。。。
}

void MainWindow::on_package_captured(int id,Packet* pkt){
    ui->textBrowser_test->append(QString("%1 captured : %2").arg(id).arg(pkt->data));
    delete pkt;
}


void MainWindow::on_pushButton_captureOptions_clicked()
{
    emit shutdown();
}
