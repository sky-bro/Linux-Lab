#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>    // for ethernet header
#include <netinet/ip.h>		// for ip header
#include <netinet/ip_icmp.h>		// for icmp header
#include <netinet/udp.h>		// for udp header
#include <netinet/tcp.h>     // for tcp header
#include <time.h>

int total, tcp, udp; // 用int 在filter port时可以安全得减去过滤去的包
unsigned int arp,icmp,igmp,other,iphdrlen;

struct sockaddr_in source,dest;

FILE* log_file;
FILE* summary_file;
FILE* mac_list_file;

time_t start_time, end_time;

struct Filter {
	int arp; // print arp
	int ethernet; // print ethernet header
	int ip; // print ip header
	int tcp; // print tcp packet
	int udp; // print udp packet
	int icmp; // print icmp packet
	int port; // only this port
} filter =  {
	.arp = 1,
	.ethernet = 0,
	.ip = 1,
	.tcp = 0,
	.udp = 0,
	.icmp = 0,
	.port = 0
};

void log_summary() {

	if (!summary_file) {
		printf("\nno summary_file\n");
		summary_file = stdout;
	}
	fprintf(summary_file, "\n\nSTART: %s", ctime(&start_time));

	fprintf(summary_file, "hello\n");

	fprintf(summary_file, "END: %s", ctime(&end_time));

	if (summary_file != stdout) {
		fclose(summary_file);
	}
}

void buf_dump(unsigned char *data, int Size)
{
    int i, j;
	for (i = 0; i < Size; i++)
	{
		if (i != 0 && i % 16 == 0) //if one line of hex printing is complete...
		{
			fprintf(log_file, " ");
			for (j = i - 16; j < i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(log_file, "%c", (unsigned char)data[j]); //if its a number or alphabet
				else
					fprintf(log_file, "."); //otherwise print a dot
			}
			fprintf(log_file, "\n");
		}
		if (i % 16 == 0)
			fprintf(log_file, " ");
		fprintf(log_file, " %02X", (unsigned int)data[i]);
		if (i == Size - 1) //print the last spaces
		{
			for (j = 0; j < 15 - i % 16; j++)
				fprintf(log_file, "   "); //extra spaces
			fprintf(log_file, " ");
			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(log_file, "%c", (unsigned char)data[j]);
				else
					fprintf(log_file, ".");
			}
			fprintf(log_file, "\n");
		}
	}
}


void print_ethernet_header(unsigned char* buffer,int buflen)
{
	if (!filter.ethernet) return;

	struct ethhdr *eth = (struct ethhdr *)(buffer);
	fprintf(log_file,"\nEthernet Header\n");
	fprintf(log_file,"\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_file,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_file,"\t|-Protocol		: %.4X\n",eth->h_proto);
}

void print_ip_header(unsigned char* buffer,int buflen)
{
	if (!filter.ip) return;

	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	iphdrlen =ip->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;     
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;     

	fprintf(log_file , "\nIP Header\n");

	fprintf(log_file , "\t|-Version              : %d\n",(unsigned int)ip->version);
	fprintf(log_file , "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	fprintf(log_file , "\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	fprintf(log_file , "\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	fprintf(log_file , "\t|-Identification    : %d\n",ntohs(ip->id));
	fprintf(log_file , "\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	fprintf(log_file , "\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	fprintf(log_file , "\t|-Header Checksum   : %d\n",ntohs(ip->check));
	fprintf(log_file , "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	fprintf(log_file , "\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
}

void print_arp_packet(unsigned char* buffer, int buflen)
{
    fprintf(log_file,"\n*************************ARP Packet******************************");
   	print_ethernet_header(buffer, buflen);

    struct arphdr *arp = (struct arphdr*)(buffer + sizeof(struct ethhdr));

   	fprintf(log_file , "\nARP Header\n");
   	fprintf(log_file , "\t|-Format of Hardware Address          : %u\n",ntohs(arp->ar_hrd));
   	fprintf(log_file , "\t|-Format of Protocol Address          : %u\n",ntohs(arp->ar_pro));
   	fprintf(log_file , "\t|-Lengh of Hardware Address     : %u\n",arp->ar_hln);
   	fprintf(log_file , "\t|-Lengh of Protocol Address     : %u\n",arp->ar_pln);
   	fprintf(log_file , "\t|-Opcode      : %u\n",ntohs(arp->ar_op));

    fprintf(log_file, "Dump\n");
	buf_dump(buffer,buflen);

    fprintf(log_file,"*****************************************************************\n\n\n");
}

void print_icmp_packet(unsigned char *buffer, int buflen)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)buffer;
	iphdrlen = iph->ihl * 4;
	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);
	fprintf(log_file,"\n*************************ICMP Packet******************************");
    print_ethernet_header(buffer, buflen);
  	print_ip_header(buffer,buflen);

	fprintf(log_file, "\nICMP Header\n");
	fprintf(log_file, "\t|-Type : %d\n", (unsigned int)(icmph->type));
	if ((unsigned int)(icmph->type) == 11)
		fprintf(log_file, " (TTL Expired)\n");
	else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
		fprintf(log_file, " (ICMP Echo Reply)\n");
	fprintf(log_file, "\t|-Code : %d\n", (unsigned int)(icmph->code));
	fprintf(log_file, "\t|-Checksum : %d\n", ntohs(icmph->checksum));
	// fprintf(log_file, "\t|-ID : %d\n",ntohs(icmph->id));
	// fprintf(log_file, "\t|-Sequence : %d\n",ntohs(icmph->sequence));
	// fprintf(log_file, "\n");
	// fprintf(log_file, "IP Header\n");
	// PrintData(Buffer, iphdrlen);
	// fprintf(log_file, "UDP Header\n");
	// PrintData(Buffer + iphdrlen, sizeof icmph);
	// fprintf(log_file, "Data Payload\n");
	// PrintData(Buffer + iphdrlen + sizeof icmph, (Size - sizeof icmph - iph->ihl * 4));
    
    fprintf(log_file, "Dump\n");
	buf_dump(buffer,buflen);
	
    fprintf(log_file,"*****************************************************************\n\n\n");
}

void print_tcp_packet(unsigned char* buffer,int buflen)
{
	struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

	if (ntohs(tcph->source) != filter.port && ntohs(tcph->dest) != filter.port) {
		--total;
		--tcp;
		return;
	}
	fprintf(log_file,"\n*************************TCP Packet******************************");
   	print_ethernet_header(buffer,buflen);
  	print_ip_header(buffer,buflen);

   	
   	fprintf(log_file , "\nTCP Header\n");
   	fprintf(log_file , "\t|-Source Port          : %u\n",ntohs(tcph->source));
   	fprintf(log_file , "\t|-Destination Port     : %u\n",ntohs(tcph->dest));
   	fprintf(log_file , "\t|-Sequence Number      : %u\n",ntohl(tcph->seq));
   	fprintf(log_file , "\t|-Acknowledge Number   : %u\n",ntohl(tcph->ack_seq));
   	fprintf(log_file , "\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(log_file , "\t|----------Flags-----------\n");
	fprintf(log_file , "\t\t|-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(log_file , "\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(log_file , "\t\t|-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(log_file , "\t\t|-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(log_file , "\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(log_file , "\t\t|-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(log_file , "\t|-Window size          : %d\n",ntohs(tcph->window));
	fprintf(log_file , "\t|-Checksum             : %d\n",ntohs(tcph->check));
	fprintf(log_file , "\t|-Urgent Pointer       : %d\n",tcph->urg_ptr);

    fprintf(log_file, "Dump\n");
	buf_dump(buffer,buflen);

    fprintf(log_file,"*****************************************************************\n\n\n");
}

void print_udp_packet(unsigned char* buffer, int buflen)
{
	struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	if (ntohs(udp->source) != filter.port && ntohs(udp->dest) != filter.port) {
		--total;
		--udp;
		return;
	}

	fprintf(log_file,"\n*************************UDP Packet******************************");
	print_ethernet_header(buffer,buflen);
	print_ip_header(buffer,buflen);
	fprintf(log_file,"\nUDP Header\n");
	
	fprintf(log_file , "\t|-Source Port    	: %d\n" , ntohs(udp->source));
	fprintf(log_file , "\t|-Destination Port	: %d\n" , ntohs(udp->dest));
	fprintf(log_file , "\t|-UDP Length      	: %d\n" , ntohs(udp->len));
	fprintf(log_file , "\t|-UDP Checksum   	: %d\n" , ntohs(udp->check));

    fprintf(log_file, "Dump\n");
	buf_dump(buffer,buflen);

	fprintf(log_file,"*****************************************************************\n\n\n");
}

void data_process(unsigned char* buffer,int buflen)
{
    struct ethhdr *eth = (struct ethhdr *)(buffer);
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof (struct ethhdr));

    if (eth->h_proto == 0x0608) { // ARP
		if (!filter.arp) return;
        ++arp;
        print_arp_packet(buffer, buflen);
    } else if (eth->h_proto == 0x0008) { // IP
        switch (ip->protocol)
        {

            case 1: //ICMP Protocol
				if (!filter.icmp) return;
                ++icmp;
                print_icmp_packet(buffer, buflen);
                break;

            case 2: //IGMP Protocol
		        ++igmp;

            case 6: //TCP Protocol
				if (!filter.tcp) return;
                ++tcp;
                print_tcp_packet(buffer, buflen);
                break;

            case 17: //UDP Protocol
				if (!filter.udp) return;
                ++udp;
                print_udp_packet(buffer, buflen);
                break;

            default:
                ++other;
                break;

        }
    } else {
        ++other;
    }

	++total;    
    printf("ARP: %d TCP: %d UDP: %d ICMP: %d IGMP: %d Others: %d Total: %d\r", arp, tcp, udp, icmp, igmp, other, total);
    fflush(stdout);
}
