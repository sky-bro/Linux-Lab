#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>

#include <linux/if_packet.h>

#include <arpa/inet.h>

struct ifreq ifreq_c,ifreq_i,ifreq_ip;
int sock_raw;
unsigned char *sendbuff;

#define IF "wlp3s0"
 
//  设置目的MAC地址
 #define DESTMAC0	0x12
 #define DESTMAC1	0x34
 #define DESTMAC2	0x56
 #define DESTMAC3	0x78
 #define DESTMAC4	0x9A
 #define DESTMAC5	0xBC
 
//  设置目的IP地址
 char destination_ip[20] = "192.168.1.1";
 char source_ip[20] = "192.168.1.123";

int total_len=0,send_len;

void get_eth_index()
{
	memset(&ifreq_i,0,sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name,IF,IFNAMSIZ-1);

	if((ioctl(sock_raw,SIOCGIFINDEX,&ifreq_i))<0)
		printf("error in index ioctl reading");

	// printf("index=%d\n",ifreq_i.ifr_ifindex);

}

void get_mac()
{
	memset(&ifreq_c,0,sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name,IF,IFNAMSIZ-1);

	if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0)
		printf("error in SIOCGIFHWADDR ioctl reading");

	// printf("My Mac Addr is: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]));
	
	// printf("1. Building ethernet header... \n");
	
	// 构造以太头
	struct ethhdr *eth = (struct ethhdr *)(sendbuff);
	// 源MAC地址
  	eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
  	eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
   	eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
   	eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
   	eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
   	eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

	// 目的MAC地址
   	eth->h_dest[0]    =  DESTMAC0;
   	eth->h_dest[1]    =  DESTMAC1;
   	eth->h_dest[2]    =  DESTMAC2;
  	eth->h_dest[3]    =  DESTMAC3;
   	eth->h_dest[4]    =  DESTMAC4;
   	eth->h_dest[5]    =  DESTMAC5;

	// 上层协议设置为IP
   	eth->h_proto = htons(ETH_P_IP);   //0x800

	total_len+=sizeof(struct ethhdr);


}

void get_data()
{
	sendbuff[total_len++]	=	'W';
	sendbuff[total_len++]	=	'H';
	sendbuff[total_len++]	=	'A';
	sendbuff[total_len++]	=	'T';
	sendbuff[total_len++]	=	'?';
}

void get_udp()
{
	// printf("3. Building UDP... \n");
	// 构造UDP头
	struct udphdr *uh = (struct udphdr *)(sendbuff + sizeof(struct iphdr) + sizeof(struct ethhdr));

	// 设置源端口目的端口
	uh->source	= htons(23451);
	uh->dest	= htons(23452);
	uh->check	= 0;

	total_len+= sizeof(struct udphdr);
	get_data();
	// 计算数据长度
	uh->len		= htons((total_len - sizeof(struct iphdr) - sizeof(struct ethhdr)));
}

// 计算校验和
unsigned short checksum(unsigned short* buff, int _16bitword)
{
	// printf("4. Calculating CheckSum... \n");
	unsigned long sum;
	for(sum=0;_16bitword>0;_16bitword--)
		sum+=htons(*(buff)++);
	do
	{
		sum = ((sum >> 16) + (sum & 0xFFFF));
	}
	while(sum & 0xFFFF0000);

	return (~sum);
}
 
 
void get_ip()
{
	// printf("2. Building IP header... \n");
	memset(&ifreq_ip,0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name, IF, IFNAMSIZ-1);
	if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0)
	{
		printf("error in SIOCGIFADDR \n");
	}
	
	// printf("My IP Addr: %s\n",inet_ntoa((((struct sockaddr_in*)&(ifreq_ip.ifr_addr))->sin_addr)));

	// 构造IP头
	struct iphdr *iph = (struct iphdr*)(sendbuff + sizeof(struct ethhdr));
	iph->ihl	= 5;
	iph->version	= 4;
	iph->tos	= 16;
	iph->id		= htons(10201);
	iph->ttl	= 64;
	iph->protocol	= 17;
	// 设置源地址
	// char *source_ip = inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)); // 本机
	// 随机地址：最后一个字节随机
	int r = rand() % 255 + 1;
	char *p = strrchr(source_ip, '.') + 1;
	*p = *(p+1) = *(p+2) = *(p+3) = 0;
	sprintf(p, "%d", r);
	iph->saddr	= inet_addr(source_ip);
	
	// 设置目的地址
	iph->daddr	= inet_addr(destination_ip); // put destination IP address
	total_len += sizeof(struct iphdr); 
	get_udp();

	iph->tot_len	= htons(total_len - sizeof(struct ethhdr));
	iph->check	= htons(checksum((unsigned short*)(sendbuff + sizeof(struct ethhdr)), (sizeof(struct iphdr)/2)));
}

int main(int argc, char **argv)
{
	srand(time(NULL));

	// 原始套接字
	sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
	if(sock_raw == -1) {
		printf("error in socket");
		exit(1);
	}

	sendbuff=(unsigned char*)malloc(64);
	memset(sendbuff, 0, 64);

    get_eth_index();  // interface number
	get_mac();
	// get_ip();

	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen   = ETH_ALEN;
	sadr_ll.sll_addr[0]  = DESTMAC0;
	sadr_ll.sll_addr[1]  = DESTMAC1;
	sadr_ll.sll_addr[2]  = DESTMAC2;
	sadr_ll.sll_addr[3]  = DESTMAC3;
	sadr_ll.sll_addr[4]  = DESTMAC4;
	sadr_ll.sll_addr[5]  = DESTMAC5;

	printf("sending...\n");
	while(1)
	{
		total_len = sizeof(struct ethhdr);
		get_ip();
		send_len = sendto(sock_raw,sendbuff,64,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
		if(send_len<0)
		{
			printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
			perror("sendto Error");
			return -1;
		}
		printf("src: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X %s   dst: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X %s  \r",
			(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]),
			source_ip,
			DESTMAC0, DESTMAC1, DESTMAC2, DESTMAC3, DESTMAC4, DESTMAC5,
			destination_ip
			);
		// break;
	}
}
