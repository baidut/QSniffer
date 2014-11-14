#include "mainwindow.h"
#include <QApplication>

/* 竞争力 wireshark 开源但基于C 效率高，但是C++开发效率更高，Qt很友好，简单，有效，重在应用
 */

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
