#include <netinet/ether.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <asm/byteorder.h>

#include "traceroute.h"
#include "raw.h"
#include "hexdump.h"
#include "checksums.h"

/*
 * We do not use the kernel's definition of the IPv6 header (struct ipv6hdr)
 * because the definition there is slightly different from what we would expect
 * (the problem is the 20bit flow label - 20bit is brain-damaged).
 *
 * Instead, we provide you struct that directly maps to the RFCs and lecture
 * slides below.
 */

typedef struct ipv6_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint32_t tc1:4, version:4, flow_label1:4, tc2:4, flow_label2:16;
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint32_t version:4, tc1:4, tc2:4, flow_label1:4, flow_label2:16;
#else
#error "You did something wrong"
#endif
	uint16_t plen;
	uint8_t nxt;
	uint8_t hlim;
	struct in6_addr src;
	struct in6_addr dst;
} __attribute__((packed)) IPV6H;

typedef struct icmp6_hdr ICMPV6H;


void build_packet(unsigned char* packet, struct in6_addr *srcip, struct in6_addr *dstip, int hopLimit, int length, int seq) {
	IPV6H* ipv6 = (IPV6H*) packet;
	ICMPV6H* icmpv6 = (ICMPV6H*) (packet+40);
	memset(ipv6, 0, 40);
	ipv6->version = 0x06;
	ipv6->plen = (uint16_t) htons(8);//8 Bytes for icmpv6
	ipv6->nxt = 58;//58 for the next header as icmpv6
	ipv6->hlim = hopLimit;
	ipv6->src = *srcip;
	ipv6->dst = *dstip;

	memset(icmpv6, 0, 8);
	icmpv6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmpv6->icmp6_code = 0;// 0 for echo request
	icmpv6->icmp6_dataun.icmp6_un_data16[1] = htons(seq);

	uint16_t cksum = icmp6_checksum((struct ip6_hdr *) packet, packet + 40,length - 40);
	icmpv6->icmp6_cksum = cksum;
				
}

int handle_reply(unsigned char* packet, int length, struct in6_addr src) {
	if (length <= 0) {
		printf("  *");//False reply, hence timeout
		return 1;
	}
	else {
		IPV6H* hdr = (IPV6H*) packet;
		char ipstring[INET6_ADDRSTRLEN];
		{
			if (memcmp(&src, &(hdr->dst), 16) != 0) {
				return 2;
			}
           
		}
		if (hdr->version != 6) {fprintf(stderr, "reject iptype\n");return 2;}
		else {
			int next = 40;
			int nexthdr = hdr->nxt;
			while (nexthdr != 58) {
				if (nexthdr != 0x00 && nexthdr != 0x2b && nexthdr != 0x3c) return 2;
				nexthdr = *(packet + next);
				next += 8 + 8 * *(packet + next + 1);
			}

			ICMPV6H* icmphdr = (ICMPV6H*) (packet + next);
			uint16_t cksm_get = icmphdr->icmp6_cksum;
			uint16_t cksm = icmp6_checksum((struct ip6_hdr *) packet,packet + next, 8);
			if (cksm != cksm_get) {
				fprintf(stderr, "reject cksum %d\n", cksm);
				return 2;
				}
				fprintf(stderr, "enter the next4\n");
			//fprintf(stderr, "the dst address of the sending is %s", inet_ntop(AF_INET6, &hdr->dst, ipstring, sizeof(ipstring)));
			switch (icmphdr->icmp6_type)
			{
			case 129:
			if ((*((char* )hdr + next + 1)) != 0) {fprintf(stderr, "reject code\n");return 2;}
			if (inet_ntop(AF_INET6, &hdr->src, ipstring, sizeof(ipstring)) == NULL) {fprintf(stderr, "invalid address\n"); printf("  *");}
			else fprintf(stdout, "  %s", ipstring);
				break;
			case 3:// time exceeded
			if (*((char* )hdr + next + 1) != 0) {fprintf(stderr, "reject code\n");return 2;}
			if (inet_ntop(AF_INET6, &hdr->src, ipstring, sizeof(ipstring)) == NULL)  {fprintf(stderr, "invalid address\n"); printf("  *");}
			else fprintf(stdout, "  %s", ipstring);
			    return 1;
			case 1:// destination unreachable
			if (inet_ntop(AF_INET6, &hdr->src, ipstring, sizeof(ipstring)) == NULL)  {fprintf(stderr, "invalid address\n"); printf("  *");}
			else fprintf(stdout, "  %s!X", ipstring);
			    break;
			default:
			   fprintf(stderr, "type does not match, type is %d", icmphdr->icmp6_type);
				printf("  *");
			}
			fprintf(stderr, "enter the next5\n");
		}
	}
	return 0;
}


/**
 * This is the entry point for student code.
 * We do highly recommend splitting it up into multiple functions.
 *
 * A good rule of thumb is to make loop bodies functions and group operations
 * that work on the same layer into functions.
 *
 * For reading from the network have a look at assignment2. Also read the
 * comments in libraw/include/raw.h
 *
 * To get your own IP address use the grnvs_get_ip6addr function.
 * This one is also documented in libraw/include/raw.h
 */
void run(int fd, const char *ipaddr, int timeoutval, int attempts,
         int hoplimit)
{
	struct in6_addr dstip;
	if ((inet_pton(AF_INET6, ipaddr, &dstip) != 1)) {
		fprintf(stderr, "Conversion of ipv6 address failed");
		exit(1);
	}

	struct in6_addr srcip = *grnvs_get_ip6addr(fd);

	uint8_t packet[1514];
	size_t length = 48;
	int seq;
	ssize_t ret;

	char str[1514];
	inet_ntop(AF_INET6, &srcip, str, sizeof(str));


	 /*(void) packet; (void) length; (void) seq;
	(void) ipname; (void) fd; (void) timeoutval; (void) attempts;
	(void) hoplimit; (void) ipaddr;*/

/*====================================TODO===================================*/
	/*
	 * TODO:
	 * 1) Initialize the addresses required to build the packet.
	 * 2) Loop over hoplimit and attempts
	 * 3) Build and send a packet for each iteration
	 * 4) Print the hops found in the specified format
	   fdf*/

	for (int i = 1; i <= hoplimit; i++) {
		int out = 0;
		fprintf(stdout, "%d", i);// Output of the hoplimit
		for (int j = 0; j < attempts; j++) {
	      int timeout = 1000 * timeoutval;
		  build_packet(packet, &srcip, &dstip, i, length, j);
		  if (( ret = grnvs_write(fd, packet, length)) < 0 ) {
			  fprintf(stderr, "grnvs_write() failed: %ld\n", ret);
			  hexdump(packet, length);
			  exit(-1);
		  }

		  unsigned char reply[1514];
		  size_t reply_length = 0;
		  int reply_res;
		  while (1) {
			reply_length = grnvs_read(fd, reply, sizeof(reply), (unsigned int*) &timeout);
			reply_res = handle_reply(reply, reply_length, srcip);
			if (reply_res != 2) break;
		  }

		  switch (reply_res)
		  {
		  case 0:
		    out = 1;
			break;
		  case 1:
		    break;
		  }
		}
		printf("\n"); //ending of the current hop
		if (out){fprintf(stderr, "out\n");break;}
	}

/*===========================================================================*/
}

int main(int argc, char ** argv)
{
	struct arguments args;
	int sock;

	if ( parse_args(&args, argc, argv) < 0 ) {
		fprintf(stderr, "Failed to parse arguments, call with "
			"--help for more information\n");
		return -1;
	}

	if ( (sock = grnvs_open(args.interface, SOCK_DGRAM)) < 0 ) {
		fprintf(stderr, "grnvs_open() failed: %s\n", strerror(errno));
		return -1;
	}

	setbuf(stdout, NULL);

	run(sock, args.dst, args.timeout, args.attempts, args.hoplimit);

	grnvs_close(sock);

	return 0;
}
