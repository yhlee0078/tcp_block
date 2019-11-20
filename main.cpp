#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>



#pragma pack(push,1)

struct etr_hdr{
	uint8_t destination_address[ETHER_ADDR_LEN];
	uint8_t source_address[ETHER_ADDR_LEN];
	uint16_t ethernet_type;
};

struct header_forked{
	struct in_addr ip_src;
	struct in_addr ip_dst;
	uint8_t reserved;
	uint8_t ip_p;
	u_short tcp_len;

};

#pragma pack(pop)

const char method[6][10]={"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
const char warning[9]="blocked";

uint8_t my_mac_address[ETHER_ADDR_LEN];

void get_mac_address(char * interface, uint8_t * addr)
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ioctl(sock, SIOCGIFCONF, &ifc);
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if(!strcmp(interface,ifr.ifr_name)){
			if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
				if (! (ifr.ifr_flags & IFF_LOOPBACK)) { 
					if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
						memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);   
						break;
                		}
            		}
        	}
    	}
    }
}

u_short calc_sum(u_char * p, uint32_t len, uint32_t offset=-1)
{
	uint32_t sum=0;
	for(int i=0;i<len;i+=2){
		if(i!=offset){
			sum+=p[i]*0x100;
			if(i+1==len){
				if(sum>0xffff){
					sum+=sum>>16;
					sum=sum&0xffff;
				}
				break;
			}
			sum+=p[i+1];
			if(sum>0xffff){
				sum+=sum>>16;
				sum=sum&0xffff;
			}
		}
	}
	return sum;
}

u_short calc_tcp_sum(u_char * p)
{
	u_short sum1=0;
	u_short sum2=0;
	u_short sum=0;
	struct header_forked pseudo;
	struct ip * ip_ptr=(struct ip *)p;
	
	pseudo.ip_src=ip_ptr->ip_src;
	pseudo.ip_dst=ip_ptr->ip_dst;
	pseudo.reserved=0;
	pseudo.ip_p=ip_ptr->ip_p;
	pseudo.tcp_len=htons(ntohs(ip_ptr->ip_len)-(ip_ptr->ip_hl)*4);
	sum1=calc_sum((u_char *)&pseudo, sizeof(header_forked));
	sum2=calc_sum((u_char *)(p+(ip_ptr->ip_hl)*4), ntohs(pseudo.tcp_len), 16);
	sum=sum1+sum2;
	
	if(sum>0xffff){
		sum+=sum>>16;
		sum=sum&0xffff;
	}
	
	return sum;
}

void make_rst_packet(u_char * p, uint32_t seq, uint32_t ack, uint32_t ip_hlen, uint32_t tcp_hlen, uint32_t option=0)
{
		
	struct etr_hdr * eth_ptr=(struct etr_hdr *)p;
	if(option)for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=my_mac_address[i];
	
	struct ip * ip_ptr=(struct ip *)(p+sizeof(struct etr_hdr));
	
	if(option){	
		uint32_t tmp_ip=ip_ptr->ip_dst.s_addr;
		ip_ptr->ip_dst.s_addr=ip_ptr->ip_src.s_addr;
		ip_ptr->ip_src.s_addr=tmp_ip;
	}
	
	ip_ptr->ip_tos=0x44;
	ip_ptr->ip_len=htons(ip_hlen+tcp_hlen);
	ip_ptr->ip_ttl=0xff;
	ip_ptr->ip_sum=htons(~calc_sum((u_char *)ip_ptr,ip_hlen,10)&0xffff);

	struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct etr_hdr)+ip_hlen);
	if(option){
		struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct etr_hdr)+ip_hlen);
		uint16_t tmp_port=tcp_ptr->th_dport;
		tcp_ptr->th_dport=tcp_ptr->th_sport;
		tcp_ptr->th_sport=tmp_port;
	}

	tcp_ptr->th_seq=seq;
	tcp_ptr->th_ack=ack;
	tcp_ptr->th_flags&=0;
	tcp_ptr->th_flags|=TH_RST;
	tcp_ptr->th_flags|=TH_ACK;
	tcp_ptr->th_win=0;
	tcp_ptr->th_sum=htons(~calc_tcp_sum((u_char*)ip_ptr)&0xffff);
	tcp_ptr->th_urp=0;
	
}

void make_fin_packet(u_char * p, uint32_t seq, uint32_t ack, uint32_t ip_hlen, uint32_t tcp_hlen, uint32_t data_len)
{
	
	struct etr_hdr * eth_ptr=(struct etr_hdr *)p;
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=my_mac_address[i];
	
	struct ip * ip_ptr=(struct ip *)(p+sizeof(struct etr_hdr));
	uint32_t tmp_ip=ip_ptr->ip_dst.s_addr;
	ip_ptr->ip_dst.s_addr=ip_ptr->ip_src.s_addr;
	ip_ptr->ip_src.s_addr=tmp_ip;
	
	ip_ptr->ip_tos=0x44;
	ip_ptr->ip_len=htons(ip_hlen+tcp_hlen+strlen(warning));
	ip_ptr->ip_ttl=0xff;
	ip_ptr->ip_sum=htons(~calc_sum((u_char *)ip_ptr,ip_hlen,10)&0xffff);
	
	struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct etr_hdr)+ip_hlen);
	memcpy(p+sizeof(struct etr_hdr)+ip_hlen+tcp_hlen, warning, strlen(warning));
	uint16_t tmp_port=tcp_ptr->th_dport;
	tcp_ptr->th_dport=tcp_ptr->th_sport;
	tcp_ptr->th_sport=tmp_port;

	tcp_ptr->th_seq=ack;
	tcp_ptr->th_ack=htonl(ntohl(seq)+data_len);
	tcp_ptr->th_flags&=0;
	tcp_ptr->th_flags|=TH_FIN;
	tcp_ptr->th_flags|=TH_ACK;
	tcp_ptr->th_win=0;
	tcp_ptr->th_sum=htons(~calc_tcp_sum((u_char*)ip_ptr)&0xffff);
	tcp_ptr->th_urp=0;	
	
}

void check(char * p, u_char * packet1, u_char * packet2, int len, u_char * fd_rstp, u_char * bk_rstp, u_char * finp, pcap_t* fp)
{

	int i;
	struct etr_hdr * a_ptr=(struct etr_hdr *)p;
	
	if(ntohs(a_ptr->ethernet_type)==ETHERTYPE_IP)
	{
		struct ip * ip_ptr=(struct ip *)(p+sizeof(struct etr_hdr));
		if((ip_ptr->ip_v==4)&&(ip_ptr->ip_p==IPPROTO_TCP))
		{
		
			unsigned int ip_hlen=(ip_ptr->ip_hl)*4;
			unsigned int ip_tlen=ip_ptr->ip_len;
			struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct etr_hdr)+ip_hlen);
			unsigned int tcp_hlen=(tcp_ptr->th_off)*4;
			unsigned int data_len=(ntohs(ip_tlen)-(ip_hlen+tcp_hlen));
			const char * data=(const char *)(p+sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
			
			uint32_t seq=tcp_ptr->th_seq;
			uint32_t ack=tcp_ptr->th_ack;
			
			for(i=0;i<6;i++)
			{
				if(!strncmp(data, method[i],strlen(method[i])))break;
			}

			if(i==6)
			{

				memcpy(packet1,p,len);
				memcpy(packet2,p,len);
									
				make_rst_packet(packet1, htonl(ntohl(seq)+data_len), ack, ip_hlen, tcp_hlen);
				make_rst_packet(packet2, ack, htonl(ntohl(seq)+data_len), ip_hlen, tcp_hlen,1);
				
				memcpy(fd_rstp, packet1, sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				memcpy(bk_rstp, packet2, sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);

				pcap_inject(fp, fd_rstp, sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				pcap_inject(fp, bk_rstp, sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);

				memset(fd_rstp, '\x0',sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				memset(bk_rstp, '\x0',sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				memset(packet1, '\x0',len);
				memset(packet2, '\x0',len);
				

			}
			else{
				memcpy(packet1,p,len);
				memcpy(packet2,p,len);
				
				make_rst_packet(packet1, htonl(ntohl(seq)+data_len), ack, ip_hlen, tcp_hlen);
				make_fin_packet(packet2, seq, ack, ip_hlen, tcp_hlen, data_len);

				memcpy(fd_rstp,packet1,sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				memcpy(finp,packet2,sizeof(struct etr_hdr)+ip_hlen+tcp_hlen+strlen(warning));

				pcap_inject(fp, fd_rstp, sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				pcap_inject(fp, finp, sizeof(struct etr_hdr)+ip_hlen+tcp_hlen+strlen(warning));

				memset(fd_rstp, '\x0',sizeof(struct etr_hdr)+ip_hlen+tcp_hlen);
				memset(finp, '\x0',sizeof(struct etr_hdr)+ip_hlen+tcp_hlen+strlen(warning));

				memset(packet1, '\x0',len);
				memset(packet2, '\x0',len);
			}							
		}
	}
}			




int main(int argc, char* argv[]) 
{
		
	if (argc != 2)
	{
		fprintf(stderr, "syntax: tcp_block <interface>\n");
		fprintf(stderr, "sample: tcp_block wlan0\n");
		exit(-1);
	}

	char* dev = argv[1];
	get_mac_address(dev, my_mac_address);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Device %s open error\n", dev, errbuf);
		exit(-1);
	}

	u_char * fd_rst_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct etr_hdr)+sizeof(struct ip)+sizeof(struct tcphdr)));
	u_char * bk_rst_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct etr_hdr)+sizeof(struct ip)+sizeof(struct tcphdr)));
	u_char * fin_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct etr_hdr)+sizeof(struct ip)+sizeof(struct tcphdr)+strlen(warning)));
	u_char * packet1=(u_char*)malloc(sizeof(u_char*)*1514);
	u_char * packet2=(u_char*)malloc(sizeof(u_char*)*1514);

	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == -1 || res == -2){
				free(fd_rst_packet);
			free(bk_rst_packet);
			free(fin_packet);
			free(packet1);
			free(packet2);
			pcap_close(handle);
			return 0;
			}
			check((char *)packet, packet1, packet2, header->caplen, fd_rst_packet, bk_rst_packet, fin_packet, handle);
	}

	free(fd_rst_packet);
	free(bk_rst_packet);
	free(fin_packet);
	free(packet1);
	free(packet2);
	pcap_close(handle);
	return 0;
}

