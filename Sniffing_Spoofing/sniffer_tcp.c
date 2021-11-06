#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#define NETWORK_ADP "br-db2becb280a0"
#define FILTRO ""

/* com base em : https://www.tcpdump.org/pcap.html */

/* IP header */
struct sniff_ip {
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;		/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define SIZE_ETHERNET 14

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
  //printf("Got Packet\n");
  const struct sniff_ip *ip; /* The IP header */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  
  if (ip->ip_p == IPPROTO_TCP){
    
    printf("Sniffer: src=%s ",inet_ntoa(ip->ip_src));
    printf("dst=%s ",inet_ntoa(ip->ip_dst));
    printf("Type: TCP");
  }
  
  if (ip->ip_p == IPPROTO_ICMP) printf("Type: ICMP");

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
