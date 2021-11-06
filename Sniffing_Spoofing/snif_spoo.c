#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


#define NETWORK_ADP "br-db2becb280a0"
#define FILTRO ""

/* com base em : https://www.tcpdump.org/pcap.html */

struct ipheader {
  unsigned char      ip_ihl:4,ip_ver:4; 
  unsigned char      ip_tos; 
  unsigned short int ip_len; 
  unsigned short int ip_ident;
  unsigned short int ip_flag:3, iph_offset:13; 
  unsigned char      ip_ttl; 
  unsigned char      ip_protocol; 
  unsigned short int ip_chksum; 
  struct  in_addr    ip_src, ip_dst;
};

struct icmpheader {
  unsigned char icmp_type; 
  unsigned char icmp_code; 
  unsigned short int icmp_chksum; 
  unsigned short int icmp_id;     
  unsigned short int icmp_seq;    
};


#define SIZE_ETHERNET 14

void send_response(struct ipheader *ip){
  u_int enable = 1;
  u_int ipH_len = ip->ip_ihl*4;

  u_int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
  
  char buffer[512];

  
  struct ipheader *resip = (struct ipheader*)buffer;
  struct icmpheader *icmp = (struct icmpheader*)(buffer + ipH_len);
  struct sockaddr_in info;

  
  memset((char*)buffer, 0, 512);
  //memset((char*)buffer,ip,ntohs(ip->ip_len));

  resip->ip_src = ip->ip_dst;
  resip->ip_dst = ip->ip_src;
  resip->ip_ttl = 30;

  icmp->icmp_type=0;

  setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));

  info.sin_family = AF_INET;
  info.sin_addr = resip->ip_dst;

  sendto(sock,resip,ntohs(resip->ip_len),0,(struct sockaddr*)&info,sizeof(info));

  close(sock);
}
 
  
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
  //printf("Got Packet\n");
  struct ipheader *ip; /* The IP header */
  ip = (struct ipheader*)(packet + SIZE_ETHERNET);

  printf("Sniffer: src=%s ",inet_ntoa(ip->ip_src));
  printf("dst=%s ",inet_ntoa(ip->ip_dst));
  
  if (ip->ip_protocol == IPPROTO_ICMP)
    {
      printf("Type: ICMP");
      send_response(ip);
    }
  

  printf("\n");
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = FILTRO;
  bpf_u_int32 net;
  
  handle = pcap_open_live(NETWORK_ADP, BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

 pcap_loop(handle, -1, got_packet, NULL);
 pcap_close(handle); //Close the handle
 return 0;
}
