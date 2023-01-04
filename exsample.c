/*  garp.c - Send IPv4 Gratuitous ARP Packet
    Usage Example: sudo ./garp eth0
    Copyright (C) 2011-2013  P.D. Buchan (pdbuchan@yahoo.com)
    Copyright (C) 2013       Seungwon Jeong (seungwon0@gmail.com)
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv4 Gratuitous ARP packet via raw socket at the link layer (ethernet frame).
// Values set for ARP request.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <errno.h>            // errno, perror()

// Define a struct for ARP header
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
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>

int
main (int argc, char **argv)
{
  char *interface;
  int i, frame_length, sd, bytes;
  arp_hdr arphdr;
  uint8_t src_ip[4],dst_ip[4], src_mac[6], dst_mac[6], ether_frame[IP_MAXPACKET];
  struct sockaddr_in *dst_ipv4, *src_ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;

  if (argc != 2) {
    printf ("Usage: %s INTERFACE\n", argv[0]);
    exit (EXIT_FAILURE);
  }

  // Interface to send packet through.
  interface = argv[1];

  // Submit request for a socket descriptor to look up interface.
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

  // Copy source IP address.
  dst_ipv4 = (struct sockaddr_in *)&ifr.ifr_addr;
  src_ipv4 = (struct sockaddr_in *)&ifr.ifr_addr; 

  //memcpy (src_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
	/*	
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
	printf("%s\n", ip);
	*/
  
  dst_ipv4->sin_addr.s_addr = inet_addr("192.168.2.137");
  memcpy(dst_ip, &dst_ipv4->sin_addr, 4 * sizeof (uint8_t));
  
  src_ipv4->sin_addr.s_addr = inet_addr("192.168.2.106");
  memcpy (src_ip, &src_ipv4->sin_addr, 4 * sizeof (uint8_t));
	

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address");
    return (EXIT_FAILURE);
  }
  
  close (sd);
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  printf ("MAC address for interface %s is", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

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

  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed");
    exit (EXIT_FAILURE);
  }

  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }
  
  char buf[128];
  recv(sd, buf, sizeof(buf), 0);
  
  close (sd);

  return (EXIT_SUCCESS);
}
