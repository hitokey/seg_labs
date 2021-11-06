#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


/* com base em: http://www.cse.iitm.ac.in/~chester/courses/19e_ns/slides/2_Spoofing.pdf */

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

int main(){

  int enable = 1;
  char buffer[1500];
  memset(buffer,0,1500);

  char *src = "10.9.0.1";
  char *dst = "10.9.0.5";
  
  struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  struct ipheader *ip = (struct ipheader *)buffer;
  struct sockaddr_in info;
  
  icmp->icmp_type = 8;
  icmp->icmp_chksum = 0;

  ip->ip_ver = 4;
  ip->ip_ihl = 5;
  ip->ip_ttl = 5;

  ip->ip_src.s_addr = inet_addr(src);
  ip->ip_dst.s_addr = inet_addr(dst);

  ip->ip_protocol = IPPROTO_ICMP;
  ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

  u_int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);

  setsockopt(sock,IPPROTO_IP, IP_HDRINCL,&enable,sizeof(enable));

  info.sin_family = AF_INET;
  info.sin_addr = ip->ip_dst;

  sendto(sock,ip,ntohs(ip->ip_len), 0, (struct sockaddr *)&info,sizeof(info));
  printf("ICMP: src=%s dst=%s ",src,dst);
  printf("type=%u ",icmp->icmp_type);
  printf("seq=%hu\n",icmp->icmp_seq);
  
  close(sock);
  return 0;
}

  

  
