#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>

typedef struct {
  unsigned char  ether_dhost[6]; /* destination host address */
  unsigned char  ether_shost[6]; /* source host address */
  unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
} ethheader;

typedef struct {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
} ipheader;

typedef struct {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
}tcpheader;

typedef struct {

   unsigned char message[100];
}msgheader;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
    {
    ethheader* eth = (ethheader*)packet;
	ipheader* ip;
	tcpheader* tcp;
	msgheader* msg;
    
        printf(
        "<<--- this is ethernet header--->>\n"
        "src Mac : %02x:%02x:%02x:%02x:%02x:%02x\n"
        "dst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n"
        "----------------------------------\n\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]
        );

        if (ntohs(eth->ether_type) == 0x0800) {
            ip =
            (ipheader*)(packet + sizeof(ethheader));
        }

        int iph_length = ip->iph_ihl * 4;

        printf(
        "<<---this is ip header--->>\n"
        "scr Ip address : %s\n"
        "dst Ip address : %s\n"
        "----------------------------------\n\n",
        inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip)
        );

        if (ip->iph_protocol == IPPROTO_TCP) {
            tcp =
            (tcpheader*)(packet + sizeof(ethheader) + iph_length);
        }

        int tcph_length = (tcp->tcp_offx2 >> 4) * 4;
        
        printf("<<---this is tcp header --->>\n"
        "src port : %d\n"
        "dst port : %d\n"
        "----------------------------------\n\n"
        , ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport)
        );
	
	    msg = 
        (msgheader*)(packet + sizeof(ethheader) + iph_length + tcph_length);

        printf(
        "<<---this msg --->>\n"
        "msg : "
        );
        for (int i = 0; msg->message[i] != '\0' && i < 100; i++) {
            printf("\\%d ", (int)msg->message[i]);
        }
        printf("\n----------------------------------\n\n");
            return;
        }

int main() {

    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);   //Close the handle
    return 0;
}