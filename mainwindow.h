#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
// #include "qsniffer.h" 隐藏内部结构，只做类的声明
#include "nic.h" // 回调函数类型无需声明 按照类型即可 但这里相关结构较复杂 如不这么做需重新定义结构，解决办法2：封装包结构

/* 要做好隔离，底层相关复杂的数据结构都封装成类，交给外部的类来操作！
 */
class QSniffer;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    //void dumpPacket(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data);

private slots:
    void on_pushButton_start_clicked(bool checked);

private:
    Ui::MainWindow *ui;
    QSniffer *qs; // 采用实例（内部）还是指针（外部）的问题，通常采用外部指针，例如此处ui
};

#endif // MAINWINDOW_H
