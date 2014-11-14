

#include <QMessageBox>
#include "nic.h"
#include "pkt.h"

/* \ERROR                   \DESCRIPTION
 * description == NULL      :No description available.
 * error in pcap_compile    :Unable to compile the packet filter. Check the syntax.
 * error in pcap_setfilter  :Error setting the filter.
 */

void dflt_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

Nic::~Nic(){
    this-> close();
}

Nic::Nic(pcap_if_t* dev,QObject *parent):QObject(parent){
    this-> dev = dev;

    this->name = dev->name;
    max_length = 65536;
    mode = PCAP_OPENFLAG_PROMISCUOUS;
    max_timeout = 1000;

    bool ret = this->open();
    Q_ASSERT(ret == true);
}

bool Nic::open(){
    this-> adhandle = pcap_open_live(
                                this-> name,            // 设备名
                                this-> max_length,      // 数据包大小限制
                                this-> mode,            // 网卡设置打开模式
                                this-> max_timeout,		// 读取超时时间
                                this-> errbuf);			// 错误缓冲

    if (this-> adhandle == NULL)
        return false;
    return true;
}

bool Nic::close(){
// TODO 关闭设备务必恢复为非混杂模式，否则数据过多。
    pcap_freecode(&(this-> fcode));
    pcap_close(this-> adhandle);
    return true;
}

Pkt* Nic::getNextPacket(){
    Q_ASSERT(adhandle!= NULL);
    struct pcap_pkthdr *header;
    u_char *pkt_data;
    int res = pcap_next_ex( adhandle, &header, (const u_char**)&pkt_data);
    if(res != 1) return NULL; // 不能无线等待下一个数据包
    Pkt* pkt = new Pkt(header,pkt_data,this); // 内存分配可能比较费时间
    return pkt;
}

void Nic::startCapture(){
    // 这个方法已经废弃
    //bool ret = this->setFilter(""); // 默认无filter tcp and udp
    //Q_ASSERT(ret == true);
    // 设备未打开 this-> adhandle == NULL
    pcap_loop(this-> adhandle, 0 ,dflt_packet_handler, NULL); // (u_char*) this
    // user 参数标识是来自哪个网卡的等等信息
}

void Nic::stopCapture(){
    pcap_breakloop(this-> adhandle);
}

bool Nic::sendPackage(u_char* content){
    int len = strlen((char*)content);
    // gen_packet(content,len); 注意填充源mac和目的mac 还有协议
    if( -1 == pcap_sendpacket(this-> adhandle, content, len) )
        return false; // 发送失败，需要释放资源
    return true;
}

bool Nic::setFilter(const char* filter, int optimize){  //"tcp"
    u_int netmask;

    /* Check the link layer. We support only Ethernet for simplicity.
    if(pcap_datalink(adhandle) != DLT_EN10MB){
        // fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        return false;
    }*/

    if (this-> dev-> addresses != NULL)
        /* 获取接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果这个接口没有地址，那么我们假设这个接口在C类网络中 */
        netmask=0xffffff;

    if (pcap_compile(this-> adhandle, &(this-> fcode), filter , optimize, netmask) <0 ){
        return false;
    }
    if (pcap_setfilter(this-> adhandle, &(this-> fcode))<0){
        pcap_freecode(&(this-> fcode));
        return false;
    }
    return true;
}

// 一个对于所有Nic类都相同的处理函数，为了向外部封装包接收回调函数结构
// 相当于一个分发包工具，先注册设备号，之后按照设备号领取对应的包处理函数(不同设备的包处理函数可以不同)
void dflt_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    // Nic* nic = (Nic*) param;                    // 提取出对应的设备指针
    // Pkt* pkt = new Pkt((struct pcap_pkthdr *)header,(u_char *)pkt_data,nic);    // 新建数据包的一个实例
    //*(nic->on_captured) (pkt);                  // 调用对应的包处理函数
    // emit nic->captured(pkt);
    // 有数据重组和交付设备的代价，但便于处理
}

// connect(nic,SINGAL(captured(pkt)),&w,on_package_captured(pkt));
// 必须让主界面类自己做 connect(nic,SINGAL(captured(pkt)),this,on_package_captured(pkt));
// 可以根据不同nic的信号进行不同槽的处理
// foreach (active_nic) connect...

