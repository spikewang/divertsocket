/** 
Cristian Draghici
cristian.draghici@gmail.com
01 aug 2007

Divert sample - alter incoming HTTP payload using divert sockets.

Some divert code based on the sample found at: 
http://www.roseindia.net/linux/tutorial/linux-howto/Divert-Sockets-mini-HOWTO-6.html

Compile using:
gcc -g -DREINJECT -DFIREWALL -c divert.m -o divert.o
gcc -o divert divert.o -framework Cocoa -framework SystemConfiguration

To run:
sudo ./divert 7866

*/

#include <SystemConfiguration/SystemConfiguration.h>
#include <Cocoa/Cocoa.h>

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>

#include <assert.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/param.h>

#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>


#define IPPROTO_DIVERT 254
#define BUFSIZE 65535

char *progname;

long packetcounter[65535];

#ifdef FIREWALL

char *fw_policy="DIVERT";
char *fw_chain="output";

struct ip_fw fw;
struct ip_fw ipfc;

int fw_sock;

char hostname[400];

@interface AddressResolution: NSObject
- (char *) getAddressOfPrimaryInterface;
@end
@implementation AddressResolution
- (char *) getAddressOfPrimaryInterface
{
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	int i;
	SCDynamicStoreContext context = { 0, (void *)self, NULL, NULL, NULL };
	SCDynamicStoreRef dynStore = SCDynamicStoreCreate(
					NULL,
					(CFStringRef) [[NSBundle mainBundle] bundleIdentifier],
					nil,
					&context);
	NSArray * allKeys;
		
	NSString * primaryInterface;
	allKeys = [(NSArray *)SCDynamicStoreCopyKeyList(dynStore, CFSTR("State:/Network/Global/IPv4")) autorelease];
	for(i=0; i<[allKeys count]; i++)
	{
		NSLog(@"Current key: %@, value: %@",
			[allKeys objectAtIndex:i],
			[(NSString *)SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease]);
			NSDictionary * dict = [(NSDictionary *)
			SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease];
			NSLog(@"PrimaryInterface: %@ value is: %@", [allKeys objectAtIndex:i], [dict objectForKey:@"PrimaryInterface"]);
			primaryInterface = (NSString *) [dict objectForKey:@"PrimaryInterface"];
	}
	
	allKeys = [(NSArray *)SCDynamicStoreCopyKeyList(dynStore,
		CFStringCreateWithFormat(kCFAllocatorDefault,
		NULL,
		CFSTR("State:/Network/Interface/%@/IPv4"),
		primaryInterface)) autorelease];
	for(i=0; i<[allKeys count]; i++)
	{
		NSLog(@"Current key: %@, value: %@",
		[allKeys objectAtIndex:i],
		[(NSString *)SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease]);
		NSDictionary * dict = [(NSDictionary *)
		SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease];
		NSLog(@"IPv4 interface: %@ value is: %@", [allKeys objectAtIndex:i], [dict objectForKey:@"Addresses"]);
		strcpy(hostname, [[[dict objectForKey:@"Addresses"] objectAtIndex:0] cString]);
	}

	[pool release];

	return hostname;
}
@end

/* innocent way of looking for a string in memory */
bool memreplace( void *haystack, void *needle, long hlen, long nlen, char * replacer )
{
//	assert(strlen(replacer) == nlen);
	bool found = false;
	void *needleStart, *i = haystack;
	
	while ( (needleStart = memchr(i, ((char *)needle)[0], hlen - (i - haystack))) != NULL) {
		if ( !memcmp(needleStart, needle, nlen) ) {
			printf("Found string at %p, Haystack is %p\n", needleStart, haystack);
			strncpy( needleStart, replacer, strlen(replacer) );
			i += strlen(replacer);
			found = true;
		}

	i++;
	}
	return found;
}

uint16_t
computeTCPChecksum(unsigned char *ipHdr, unsigned char *tcpHdr)
{
    uint32_t sum = 0;
    uint16_t count = ipHdr[2] * 256 + ipHdr[3];
    unsigned char *addr = tcpHdr;
    unsigned char pseudoHeader[12];

    /* Count number of bytes in TCP header and data */
    count -= (ipHdr[0] & 0x0F) * 4;

    memcpy(pseudoHeader, ipHdr+12, 8);
    pseudoHeader[8] = 0;
    pseudoHeader[9] = ipHdr[9];
    pseudoHeader[10] = (count >> 8) & 0xFF;
    pseudoHeader[11] = (count & 0xFF);

    /* Checksum the pseudo-header */
    sum += * (uint16_t *) pseudoHeader;
    sum += * ((uint16_t *) (pseudoHeader+2));
    sum += * ((uint16_t *) (pseudoHeader+4));
    sum += * ((uint16_t *) (pseudoHeader+6));
    sum += * ((uint16_t *) (pseudoHeader+8));
    sum += * ((uint16_t *) (pseudoHeader+10));

    /* Checksum the TCP header and data */
    while ( count > 1 ) {
		sum += * (uint16_t *) addr;
		addr += 2;
		count -= 2;
    }
    if ( count > 0 ) {
		sum += *addr;
    }

    while ( sum >> 16 ) {
		sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t) (~sum & 0xFFFF);
}

/* remove the firewall rule when exit */
void intHandler (int signo) 
{

	if ( setsockopt(fw_sock, IPPROTO_IP, IP_FW_DEL, &fw, sizeof(fw)) == -1 ) 
	{
		fprintf(stderr, "%s: could not remove rule: %s\n", progname, strerror(errno));
		exit(2);
	}

	close(fw_sock);
	exit(0);
}

#endif

int main(int argc, char** argv) 
{
	int fd, rawfd, fdfw, ret, n;
	int on = 1;
	struct sockaddr_in bindPort, sin;
	int sinlen;
	struct ip * hdr; //iphdr *hdr;
	unsigned char packet[BUFSIZE];
	struct in_addr addr;
	int i, direction;
	struct ip_mreq mreq;

	struct hostent *temp_hostent;

	if ( argc != 2 ) {
		fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
		exit(1); 
	}

	progname = argv[0];

	for ( i = 0; i < 65535; i++ )
		packetcounter[i] = 0;

	fprintf(stderr, "%s:Creating a socket\n", argv[0] );
	
	/* open a divert socket */
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
	
	if ( fd == -1 ) {
		fprintf(stderr,"%s:We could not open a divert socket\n",argv[0]);
		exit(1);
	}

	AddressResolution * m = [[AddressResolution alloc] init];
	
	if ( (temp_hostent = gethostbyname([m getAddressOfPrimaryInterface])) == NULL ) {
		fprintf(stderr,"%s:We could not get host by name: %s\n",argv[0], hostname);
		exit(1);
	}

	bindPort.sin_family = AF_INET;
	bindPort.sin_port = htons( atol(argv[1]) );
	bindPort.sin_addr.s_addr = *(in_addr_t*)(temp_hostent->h_addr);

	fprintf(stderr, "%s:Binding a socket\n", argv[0]);
	
	ret = bind( fd, (struct sockaddr *)&bindPort, sizeof(bindPort) );

	if ( ret != 0 ) {
		close(fd);
		fprintf(stderr, "%s: Error bind(): %s",argv[0],strerror(ret));
		exit(2);
	}

	//struct hostent *dst_hostent = gethostbyname("69.16.137.252");

#ifdef FIREWALL
	/* fill in the rule first */
	bzero( &fw, sizeof(struct ip_fw) );

	fw.version = IP_FW_CURRENT_API_VERSION;
	fw.fw_number = 1;

	// Catch all outgoing packet
	//fw.fw_src.s_addr = *(in_addr_t*)(dst_hostent->h_addr); 
	//fw.fw_smsk.s_addr = ~0;
	
	// Catch all incoming packet
	//fw.fw_dst.s_addr = *(in_addr_t*)(temp_hostent->h_addr); 
	//fw.fw_dmsk.s_addr = ~0;
	//fw.fw_dst.s_addr = *(in_addr_t*)(dst_hostent->h_addr); 
	//fw.fw_dmsk.s_addr = ~0;

	//fw.fw_prot = IPPROTO_TCP;
	fw.fw_prot = IPPROTO_IP;

	//fw.fw_flg = IP_FW_F_DIVERT | IP_FW_F_OUT;
	fw.fw_flg = IP_FW_F_DIVERT | IP_FW_F_IN | IP_FW_F_OUT;
	fw.fw_un.fu_divert_port = htons( bindPort.sin_port );

	//fw.fw_uar.fw_pts[0] = 80;
	//fw.fw_nports = 1;


	/* open a socket */
	if ( ( fw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW) ) == -1 ) {
		fprintf( stderr, "%s: could not create a raw socket: %s\n", argv[0], strerror(errno) );
		exit(2);
	}

	/* write a rule into it */
	if ( setsockopt(fw_sock, IPPROTO_IP, IP_FW_ADD, &fw, sizeof(fw)) == -1 ) {
		fprintf(stderr, "%s could not set rule: %s\n", argv[0], strerror(errno));
		exit(2);
	}
 
	/* install signal handler to delete the rule */
	signal(SIGINT, intHandler);

#endif /* FIREWALL */
  
	printf("%s: Waiting for data...\n",argv[0]);
	
	/* read data in */
	sinlen = sizeof(struct sockaddr_in);
	
	while( 1 ) {
		n = recvfrom(fd, packet, BUFSIZE, 0, (struct sockaddr *)&sin, (socklen_t *)&sinlen);
		hdr = (struct ip *)packet;

		addr = hdr->ip_src;
		printf("%s: Src addr: %s",argv[0], inet_ntoa(addr));

		addr = hdr->ip_dst;
		printf(" Dst addr: %s", inet_ntoa(addr));

		/* TCP or UDP? */
		if ( hdr->ip_p == IPPROTO_TCP ) {
			struct tcphdr * tcpptr;
			tcpptr = (struct tcphdr *) (packet + sizeof(struct ip));
			
			packetcounter[ (tcpptr->th_sport) ] += n;

			printf(" src port: %d dst port: %d count: %ld\n", 
				htons(tcpptr->th_sport), 
				htons(tcpptr->th_dport),
				packetcounter[htons(tcpptr->th_sport)]);

			unsigned char * data = packet + sizeof(struct ip) + sizeof(struct tcphdr);
			int m = 0;
			

			printf("\n");
			printf("Got packet:\n");
			for ( m = 0; m < n; m++ ) {
				//printf("%X", (data[m] > 31 && data[m] < 127) ? data[m] : '_'); 
				printf("%X ", data[m]);
				data[m] = 0;
			}
			
			//memreplace(data, "LoudHush", n, strlen("LoudHush"), "l0UDhUSH");
			//if ( memreplace(data, "www.sex.com/sites/", n, strlen("www.sex.com/sites/"), "www.nba.com") ) {
			//	n = n - 7;
			//}
			
			// Zero the tcp checksum before check-summing the packet otherwise the checksum is wrong
			//tcpptr->th_sum = 0;
			//unsigned short cs = computeTCPChecksum(hdr, tcpptr);
			
			//printf("Computed checksum: %d\n", cs);
			//tcpptr->th_sum = cs;
		}
		else if ( hdr->ip_p == IPPROTO_UDP ) {
			//sinlen = sizeof(struct udphdr);
			
			//struct udphdr * udpptr;
			//udpptr = (struct udphdr *)( packet + sizeof(struct ip) );

//			printf("%s: UDP src port: %d dst port: %d\n", argv[0], htons(udpptr->uh_sport), htons(udpptr->uh_dport));
		}

		/* reinjection */


#ifdef REINJECT
		printf("%s Reinjecting DIVERT %i bytes\n", argv[0], n);

		printf("\n");
		
		int m = 0;

		//printf("rejected packet: \n");
		for ( m = sizeof(struct ip) + sizeof(struct tcphdr); m < n; m++ ) {
		//for ( m = 0; m < n; m++ ) {
			printf("%c", (packet[m] > 31 && packet[m] < 127) ? packet[m] : '_'); 
		}
		
		printf("\n");
			
		n = sendto( fd, packet, n, 0, (struct sockaddr *)&sin, sinlen );

		printf("%s: %i bytes reinjected.\n", argv[0], n); 

		if ( n <= 0 ) 
			printf("%s: Oops: reinject errno = %i\n", argv[0], errno);
#endif
	}
}




