#include <iostream>
#include <cstdio>
#include <netinet/in.h>
#include <cstdbool>
#include <pcap.h>
#include <string>
#include "mac.h"
#include <vector>
#include <fstream>

using namespace std;

struct BFFrame {
    uint8_t ver;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
    uint16_t data_rate;
    uint16_t tx_flag;
    uint8_t type;
    uint8_t flag;
    uint16_t duration;
    Mac da;
    Mac sa;
    Mac bssid;
    uint16_t seq;
    uint16_t timestamp1;
    uint16_t timestamp2;
    uint16_t timestamp3;
    uint16_t timestamp4;
    uint16_t itv;
    uint16_t cap;
    uint8_t tag_num;
    uint8_t tag_len;
    u_char ssid[255];
};

void print_syntax() {
    cout << "syntax : beacon-flood <interface> <ssid-list-file>" << endl;
    cout << "sample : beacon-flood mon0 ssid-list.txt" << endl;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_syntax();        
        exit(-1);
    }

    vector<string> bc_list;
    char bc_name[100];

    ifstream fin(argv[2]);
    while(fin.getline(bc_name, 100)) {
        bc_list.push_back(string(bc_name));
        cout << bc_name << endl;
    }
    fin.close();

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

    struct BFFrame bff;

    while(1) {
        for (int num = 0; num < bc_list.size(); num++) {
            bff.ver = 0x00;
            bff.pad = 0x00;
            bff.len = 0x000c;
            bff.present = 0x00008004;
            bff.data_rate = 0x0002;
            bff.tx_flag = 0x0018;

            bff.type = 0x80;
            bff.flag = 0x00;
            bff.duration = 0x0000;
            bff.da = Mac("FF:FF:FF:FF:FF:FF");
            bff.sa = Mac("11:11:11:11:11:11");
            bff.bssid = Mac("22:22:33:44:55:66");
            bff.seq = 0x0000;

            bff.timestamp1 = 0;
            bff.timestamp2 = 0;
            bff.timestamp3 = 0;
            bff.timestamp4 = 0;
            bff.itv = 0x00;
            bff.cap = 0x00;
            bff.tag_num = 0x0;
            bff.tag_len = bc_list[num].length();
            for (int num1 = 0; num1 < bc_list[num].length(); num1++) {
                bff.ssid[num1] = bc_list[num][num1];
            }
            bff.ssid[bc_list[num].length() + 0] = 0x01;
            bff.ssid[bc_list[num].length() + 1] = 0x04;
            bff.ssid[bc_list[num].length() + 2] = 0x82;
            bff.ssid[bc_list[num].length() + 3] = 0x84;
            bff.ssid[bc_list[num].length() + 4] = 0x8b;
            bff.ssid[bc_list[num].length() + 5] = 0x96;
            bff.ssid[bc_list[num].length() + 6] = 0x03;
            bff.ssid[bc_list[num].length() + 7] = 0x01;
            bff.ssid[bc_list[num].length() + 8] = 0x0c;
            bff.ssid[bc_list[num].length() + 9] = 0x04;
            bff.ssid[bc_list[num].length() + 10] = 0x06;
            bff.ssid[bc_list[num].length() + 11] = 0x01;
            bff.ssid[bc_list[num].length() + 12] = 0x02;
            bff.ssid[bc_list[num].length() + 13] = 0x00;
            bff.ssid[bc_list[num].length() + 14] = 0x00;
            bff.ssid[bc_list[num].length() + 15] = 0x00;
            bff.ssid[bc_list[num].length() + 16] = 0x00;
            bff.ssid[bc_list[num].length() + 17] = 0x05;
            bff.ssid[bc_list[num].length() + 18] = 0x04;
            bff.ssid[bc_list[num].length() + 19] = 0x00;
            bff.ssid[bc_list[num].length() + 20] = 0x01;
            bff.ssid[bc_list[num].length() + 21] = 0x00;
            bff.ssid[bc_list[num].length() + 22] = 0x00;


            int packet_size = sizeof(struct BFFrame) - 255 + bc_list[num].length() + 20;

            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&bff), packet_size);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }
        }
    }
}