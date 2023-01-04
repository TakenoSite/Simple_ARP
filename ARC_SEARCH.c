#include <net/if_arp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           
#include <string.h>         

#include <sys/types.h>        
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>           
#include <linux/if_packet.h>  
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

typedef struct _arp_hdr arp_hdr;

struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};


// Define some constants.
#define ETH_HDRLEN 14      
#define IP4_HDRLEN 20      
#define ARP_HDRLEN 28      
#define ARPOP_REQUEST 1    

void show_addr(struct sockaddr_in *addr_in){
	size_t buf_size = 32;
	char buf[buf_size];
	memset(buf, 0, buf_size);
	inet_ntop(AF_INET, &addr_in->sin_addr, buf, buf_size);
	printf("%s\n", buf);
}

int SockTimeout(int sockfd,int sec, int usec)
{
	struct timeval tv;
	int net_select;
	fd_set readfds;
	
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	net_select = select(sockfd + 0x01, &readfds, NULL, NULL, &tv);
	return net_select;
};


int search(char *ip_info){

	int j, frame_length, sd, bytes;
	arp_hdr arphdr;
	uint8_t src_ip[4],dst_ip[4], src_mac[6], dst_mac[6], ether_frame[IP_MAXPACKET];

	struct sockaddr_in *src_ipv4, dst_ipv4;
	struct sockaddr_ll device;
	struct ifreq ifr;
	
	char buf[128], resolve[1024];
	char *interface = "eth0";
	char dst_host[16];
	char ip[INET_ADDRSTRLEN];
	
	FILE *OUTPUT = fopen("resolve.txt","a");
	
	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl()");
		exit (EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its IPv4 address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sd, SIOCGIFADDR, &ifr) < 0) {
		perror ("ioctl() failed to get source IP address");
		return (EXIT_FAILURE);
	}
	
	src_ipv4 = (struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(src_ip, &src_ipv4->sin_addr, 4 * sizeof(uint8_t));
	for(j=0; j<255; j++){		
		memset(dst_host, 0, sizeof(dst_host));
		sprintf(dst_host, "%s.%d", ip_info,j);
		
		dst_ipv4.sin_addr.s_addr = inet_addr(dst_host);
		//show_addr(&dst_ipv4);
		memcpy(dst_ip, &dst_ipv4.sin_addr, 4 * sizeof(uint8_t));
		memset (&ifr, 0, sizeof (ifr));
		snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
		
		if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
			perror ("ioctl() failed to get source MAC address");
			return (EXIT_FAILURE);
		}
		
		memset(&src_mac, 0, sizeof(src_mac));
		memset(&device, 0, sizeof(device));

		memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
		/*
		//printf ("MAC address for interface %s is", interface);
		for (i=0; i<5; i++) {
			printf ("%02x:", src_mac[i]);
		}
		*/
		if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
			perror ("if_nametoindex() failed to obtain interface index");
			exit (EXIT_FAILURE);
		}
		//printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
	
		memset(&arphdr, 0, sizeof(arphdr));	
		memset (dst_mac, 0xff, 6 * sizeof (uint8_t));
		memcpy (&arphdr.sender_ip, src_ip, 4 * sizeof (uint8_t));
		memcpy (&arphdr.target_ip, dst_ip, 4 * sizeof (uint8_t));
			
		device.sll_family = AF_PACKET;
		memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
		device.sll_halen = htons (6);

		  // arp hdr set
		arphdr.htype = htons (1);
		arphdr.ptype = htons (ETH_P_IP);
		arphdr.hlen = 6;
		arphdr.plen = 4;
		arphdr.opcode = htons (ARPOP_REQUEST);
		
		memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));
		memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));
		  
		frame_length = 6 + 6 + 2 + ARP_HDRLEN;

		memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
		memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
		  
		ether_frame[12] = ETH_P_ARP / 256;
		ether_frame[13] = ETH_P_ARP % 256;

		memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
		if((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
			perror ("socket() failed");
			exit (EXIT_FAILURE);
		}

		if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
		
		memset(buf, 0, sizeof(buf));
		
		//解決速度は、早くなるけど精度が微妙になる 
		int timewatch = SockTimeout(sd, 1, 0);
		if(timewatch == 0){
			continue;
		}
		
		recv(sd, buf, sizeof(buf), 0);
		struct ether_arp *ea, e;
		memset(&e, 0, sizeof(e));
		
		ea = (struct ether_arp*)(buf + sizeof(struct ether_header));
		if(ea->arp_op == htons(ARPOP_REPLY)){
            inet_ntop(AF_INET, &ea->arp_spa, ip, sizeof(ip));
			//sprintf("done  %s\n", ip);
			
			strcat(ip, "\n");
			fwrite(ip, strlen(ip), 1, OUTPUT);
	
		}
	}
	
	fclose(OUTPUT);
	return 0;
}

int main(int argc, char **argv){
	if(argc != 2){ 
		printf("Usage :failed format, exsample : {192.168.2}\n");
		exit(EXIT_FAILURE);
	}
	
	pid_t pid;
	pid = fork();

	switch(pid){
		case 0:
			puts("[*] start");
			search(argv[1]);
	}
	
	return 0;
}
