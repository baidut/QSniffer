#-------------------------------------------------
#
# Project created by QtCreator 2014-11-06T13:54:10
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qsniffer
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    qsniffer.cpp \
    nic.cpp \
    pkt.cpp \
    capturethread.cpp

HEADERS  += mainwindow.h \
    qsniffer.h \
    nic.h \
    pkt.h \
    capturethread.h

FORMS    += mainwindow.ui

LIBS += E:\Sniffer\sniffer_module_test\Packet.lib
LIBS += E:\Sniffer\sniffer_module_test\wpcap.lib
