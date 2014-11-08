#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qsniffer.h" //隐藏内部结构，只做类的声明
#include <QMessageBox>

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

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->qs = new QSniffer;
    QStringList dev_list = this->qs->getDeviceList();
/* 原来是只打开一个设备 采用comboBox选择 添加多选设备支持后，改成了可以多选的列表
    ui->comboBox_dev->addItems(dev_list);
*/
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
           }
        }
        //qs->setActionOnCaptured(showList);
        qs->startCapture();
    }
    else{
        ui->pushButton_start->setText("Start");
        qs->stopCapture();
    }
}
