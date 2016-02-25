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
using namespace std;

//多了好多换行
struct pcap_file_header
{
    //不在意其细节
    char data[24];
}__attribute__((__packed__));

struct timestamp
{
	uint32_t timestamp_s;
	uint32_t timestamp_ms;
}__attribute__((__packed__));

struct pcap_header
{
	timestamp ts;
	uint32_t capture_len;
	uint32_t real_len;
}__attribute__((__packed__));

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
    char ip_cstr[15];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(ip_cstr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    ip_str = ip_cstr;
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

void printPcapHeader(const pcap_header& ph)
{
    cout << "timestamp_s: " << ph.ts.timestamp_s << endl;
    cout << "timestamp_ms: " << ph.ts.timestamp_ms << endl;
    cout << "capture_len: " << ph.capture_len << endl;
    cout << "real_len: " << ph.real_len << endl;
}

int main()
{
    ifstream in;
    string pcap_file;
    cout << "请输入待分析的pcap文件名:";
    cin >> pcap_file;
    if(_access("result", F_OK) == 0)//存在result文件夹
        system("RD /s/q result");//删除当前目录的result文件夹
    _mkdir("result");
    _mkdir("result\\tcp");
    _mkdir("result\\udp");

    clock_t t_start, t_end;
    t_start = clock();

    in.open(pcap_file, ios::in | ios::binary);
    if(!in.is_open()) {
        cout << "无法打开 “" + pcap_file + "” ,请确认文件名输入是否正确!" << endl;
        system("pause");
        exit(0);
    }
    //struct _stat info;
    //_stat(pcap_file.c_str(), &info);
    //long double  size = info.st_size;
    //cout << size << endl;
    //cout<< "文件大小:" << (int64_t)size / 1024 / float(1024)<< "MB" << endl << "正在分析...\n";
    cout <<  "正在解析pcap文件......";
    pcap_file_header pfh;
    in.read((char*)&pfh, sizeof(pfh));
    vector<package> package_list;
    long h = 1;
    long k = 0;
    //1742789
    while(!in.eof()) {
        package pg;
        pcap_header ph;
        if(in.read((char*)&ph, sizeof(ph)).gcount() == 0) break;

        pg.ph = ph;
        const uint32_t total_len = static_cast<uint32_t>(sizeof(int32_t) + ph.capture_len);
        pg.pd = static_cast<pcap_data*>(::malloc(total_len));
        pg.pd->len = ph.capture_len;
        in.read(pg.pd->data, ph.capture_len);
        package_list.push_back(pg);
        if(k >= 1742000) {
            printPcapHeader(ph);
            printf("%ld\n", k++);
            continue;
        }
        if(k++ % 10000 == 0)
            printf("%d\n", h+= 10000);

    }
    in.close();
    cout << "解析完毕\n";
    cout << "正在分组会话......";
    map<five, vector<package> > package_group;
    for(size_t i = 0; i < package_list.size(); i++) {
        five f;
        f.protcol = package_list[i].pd->data[23];
        memcpy(&f.ip1, &package_list[i].pd->data[26], 4);
        memcpy(&f.ip2, &package_list[i].pd->data[30], 4);
        memcpy(&f.port1, &package_list[i].pd->data[34], 2);
        memcpy(&f.port2, &package_list[i].pd->data[36], 2);
        if((int) package_list[i].pd->data[23] == 6 ||
           (int) package_list[i].pd->data[23] == 17 ) {
                package_group[f].push_back(package_list[i]);
           }
    }

    cout << "会话分组完毕，正在生成结果...(见 result 文件夹)" << endl;

    ofstream report;
    report.open("result\\report.txt", ios::out);
    map<five, vector<package> >::iterator it;
    for(it = package_group.begin(); it != package_group.end(); ++it) {
        ofstream pcap;
        string file_name;
        string protcol;
        string dir;
        ostringstream port1, port2;
        port1 << dec << swapInt16((*it).first.port1);
        port2 << dec << swapInt16((*it).first.port2);
        if((*it).first.protcol == 6) {
            protcol = "tcp";
            dir = "result\\tcp\\";
        } else {
            protcol = "udp";
            dir = "result\\udp\\";
        }
        file_name = "[" + protcol + "][" + print_ip((*it).first.ip1) + "][" + port1.str() + "][" + print_ip((*it).first.ip2) + "][" + port2.str() + "].pcap";
        pcap.open(dir + file_name, ios::out | ios::binary);
        pcap.write((char*)&pfh, sizeof(pfh));
        vector<package>::iterator it2;
        for(it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
            pcap.write((char*)&(*it2).ph, sizeof(pcap_header));
            pcap.write((char*)(*it2).pd->data, (*it2).pd->len);
        }
        report << "write " + file_name + " done\n";
        pcap.close();
    }
    report.close();
    t_end = clock();
    cout << "总共耗时：" << double(t_end - t_start) / CLOCKS_PER_SEC << "秒." <<endl;
    system("PAUSE");

}
