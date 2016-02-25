#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdlib>
#include <string>
#include <cstring>
#include <cstdio>
#include <vector>
#include <cstdint>
#include <map>
#include <sstream>
#include <io.h>
#include <sys/stat.h>
#include <direct.h>

using namespace std;

//多了好多换行
struct pcap_file_header
{
    //不在意其细节
    char data[24];
};

struct timestamp
{
	uint32_t timestamp_s;
	uint32_t timestamp_ms;
};

struct pcap_header
{
	timestamp ts;
	uint32_t capture_len;
	uint32_t real_len;
};

struct pcap_data
{
    int32_t len;
    char data[0];//同上，直接忽略其细节
};


struct package
{
    pcap_header ph;
    pcap_data *pd;
};

string print_ip(int32_t ip)
{
    unsigned char bytes[4];
    string ip_str;
    char ip_cstr[20];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
	//printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
	sprintf_s(ip_cstr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    //sprintf(ip_cstr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    ip_str = ip_cstr;
	//printf("%\n",ip_cstr);
    return ip_str;
}

int32_t swapInt32(int32_t value)
{
     return ((value & 0x000000FF) << 24) |
            ((value & 0x0000FF00) << 8)  |
            ((value & 0x00FF0000) >> 8)  |
            ((value & 0xFF000000) >> 24) ;
}
uint16_t swapInt16(uint16_t value)
{
     return ((value & 0x00FF) << 8) |
            ((value & 0xFF00) >> 8) ;
}

struct five
{
    unsigned char protcol;
    int32_t ip1;
    int32_t ip2;
    uint16_t port1;
    uint16_t port2;
    bool operator<(const five& __x) const {
        return (ip1+ip2+port1+port2) <
               (__x.ip1+__x.ip2+__x.port1+__x.port2);
    }
};


