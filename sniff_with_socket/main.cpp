#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <argp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <time.h>
#include "sniffer.h"
#include "parse_args.h"
#include <map>
#include <string>
#include <iostream>

using namespace std;

int sock_r;
char tmp_mac[50];

extern map<string, int> MACs;

void sighandler(int signum) {
	end_time = time(NULL);
	log_summary();
	close(sock_r);
	fclose(log_file);
	fclose(mac_list_file);
	printf("\nExiting peacefully...\n");
	exit(0);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sighandler);

    struct sockaddr saddr;
	int saddr_len, buflen;

	unsigned char* buffer = (unsigned char *)malloc(65536); 
	memset(buffer,0,65536);

	struct arguments args;
	/* Default values. */
	args.all = 0; // 默认只显示arp和ip头
	args.dump = 0; // 默认不dump包数据
	args.ethernet = 0; // 默认不包含ethernet头
	args.port = 0;
	args.interface = NULL; // 默认使用默认网络接口
	// 只解析这些协议类型（NULL表示不显示声明，以-a参数为准--包含所有协议或只有arp与ip）
	// udp tcp arp ip icmp other
	args.protocols = NULL;
	
	argp_parse (&argp, argc, argv, 0, 0, &args);



	filter.dump = args.dump;
	filter.port = args.port;
	
	filter.ethernet = args.ethernet;
	if (args.all) {
		// filter.arp = filter.icmp = filter.ip = filter.other = filter.tcp = filter.udp = 1;
		filter.icmp = filter.other = filter.tcp = filter.udp = 1;
	}
	if (args.protocols) {
		filter.icmp = filter.other = filter.tcp = filter.udp = 0;
		for (int i = 0; args.protocols[i]; ++i) {
			if (!strcmp("arp", args.protocols[i])) {
				filter.arp = 1;
			} else if (!strcmp("ip", args.protocols[i])) {
				filter.ip = 1;
			} else if (!strcmp("tcp", args.protocols[i])) {
				filter.tcp = 1;
			} else if (!strcmp("udp", args.protocols[i])) {
				filter.udp = 1;
			} else if (!strcmp("icmp", args.protocols[i])) {
				filter.icmp = 1;
			} else if (!strcmp("other", args.protocols[i])) {
				filter.other = 1;
			}
		}
	}

	sock_r=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
	if(sock_r<0)
	{
		printf("error in socket, you may need to use sudo\n");
		return -1;
	}

	if (args.interface) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, IFNAMSIZ, args.interface);
		if (setsockopt(sock_r, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
		{
			perror("Server-setsockopt() error for SO_BINDTODEVICE");
			printf("%s\n", strerror(errno));
			close(sock_r);
			exit(-1);
		}
	}
	
	log_file=fopen("log.txt","a");
	if(!log_file)
	{
		printf("unable to open log.txt\n");
		return -1;
	}

    summary_file=fopen("summary.txt","a");
    if(!summary_file)
	{
		printf("unable to open summary.txt\n");
		return -1;
	}

    mac_list_file=fopen("mac_list.txt","a+t");
    if(!mac_list_file)
	{
		printf("unable to open mac_list.txt\n");
		return -1;
	}
	
	while (fscanf(mac_list_file, "%s", &tmp_mac) == 1) {
		MACs.insert(pair< string, int >(tmp_mac, 1));
	}

    start_time = time(NULL);
	
	while(1)
	{
		saddr_len=sizeof saddr;
		buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);
		if(buflen<0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(log_file);
		// fflush(summary_file);
		fflush(mac_list_file);
		data_process(buffer,buflen);
	}
	end_time = time(NULL);
	log_summary();
	close(sock_r);
    fclose(log_file);
    fclose(mac_list_file);
	printf("DONE!!!!\n");
}
