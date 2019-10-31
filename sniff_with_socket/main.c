#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <string.h>
#include <time.h>
#include "sniffer.h"

int sock_r;

void sighandler(int signum) {
   close(sock_r);
   fclose(log_file);
   fclose(mac_list_file);
   printf("\nExiting peacefully...\n");
   exit(0);
}

int main()
{
    signal(SIGINT, sighandler);

    struct sockaddr saddr;
	int saddr_len, buflen;

	unsigned char* buffer = (unsigned char *)malloc(65536); 
	memset(buffer,0,65536);

	log_file=fopen("log.txt","w");
	if(!log_file)
	{
		printf("unable to open log.txt\n");
		return -1;
	}

    // summary_file=fopen("summary.txt","w");
    // if(!summary_file)
	// {
	// 	printf("unable to open summary.txt\n");
	// 	return -1;
	// }

    mac_list_file=fopen("mac_list.txt","rw");
    if(!mac_list_file)
	{
		printf("unable to open mac_list.txt\n");
		return -1;
	}

    time_t It = time(NULL);
    printf("Start at: %s", ctime(&It));

	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r<0)
	{
		printf("error in socket\n");
		return -1;
	}

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
	close(sock_r);
    fclose(log_file);
    fclose(mac_list_file);
	printf("DONE!!!!\n");
}
