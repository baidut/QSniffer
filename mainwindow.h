#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
// #include "qsniffer.h" 隐藏内部结构，只做类的声明

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

private slots:
    // void on_pushButton_openDev_clicked();

private:
    Ui::MainWindow *ui;
    QSniffer *qs; // 采用实例（内部）还是指针（外部）的问题，通常采用外部指针，例如此处ui
};

#endif // MAINWINDOW_H
