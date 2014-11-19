#-------------------------------------------------
#
# Project created by QtCreator 2014-11-19T16:02:23
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QSniffer
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

win32{
# ntohs ntohl ws2_32.lib
# LIBS += WS2_32.LIB
    LIBS += -lWs2_32
    LIBS += E:\Sniffer\sniffer_module_test\Packet.lib
    LIBS += E:\Sniffer\sniffer_module_test\wpcap.lib
}
unix{
 LIBS += -L/usr/local/lib -lpcap
}
