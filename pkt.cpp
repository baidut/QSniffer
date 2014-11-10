
#include "pkt.h"

char* Pkt::time(){ // QString QDate
struct tm *ltime;
char* timestr = new char[16];
time_t local_tv_sec;
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    sprintf(timestr,"%s%.6d",timestr,header->ts.tv_usec);
    return timestr;
}

int Pkt::len(){
    return header->len;
}

u_char* Pkt::data(){
    return pkt_data;
}
