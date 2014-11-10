
#include "nic.h"
#include "pkt.h"

/* \ERROR                   \DESCRIPTION
 * description == NULL      :No description available.
 * error in pcap_compile    :Unable to compile the packet filter. Check the syntax.
 * error in pcap_setfilter  :Error setting the filter.
 */

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

Nic::~Nic(){
    this-> close();
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

void Nic::startCapture(){
    pcap_loop(this-> adhandle, 0 ,packet_handler, (u_char*) this);
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

bool Nic::setFilter(char* filter, int optimize = 1){  //"tcp"
    u_int netmask;

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
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    Nic* nic = (Nic*) param;                    // 提取出对应的设备指针
    Pkt* pkt = new Pkt((struct pcap_pkthdr *)header,(u_char *)pkt_data,nic);    // 新建数据包的一个实例
    //*(nic->on_captured) (pkt);                  // 调用对应的包处理函数
    // 有数据重组和交付设备的代价，但便于处理
}


