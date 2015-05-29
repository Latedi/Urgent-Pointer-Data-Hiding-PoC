#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
 
#define MAX_PACKAGE_SIZE 65535
#define S_PORT 8999
#define D_PORT 5000
 
unsigned short calc_ipv4_check(unsigned short *buffPointer, int buffLen);
 
int main (int argc, char* argv[])
{
        //Create variables and put pointers to the headers in the buffer
        char destIP[] = "127.0.0.1";
        char sourceIP[] = "127.0.0.1";
        struct tcphdr *tcp_header;
        void *buffer = (void *) malloc(MAX_PACKAGE_SIZE);
        memset(buffer, 0, MAX_PACKAGE_SIZE);
        void *recvBuffer = (void *) malloc(MAX_PACKAGE_SIZE);
        memset(recvBuffer, 0, MAX_PACKAGE_SIZE);
        struct iphdr *ip_header_in = (struct iphdr *) recvBuffer;
        struct tcphdr *tcp_header_in;
        struct sockaddr socket_address;
        socklen_t sock_addr_len = sizeof(socket_address);
 
        //This is what will be sent. Message as TCP data every packet and
        //secret_message split up and put into the TCP urgent pointer field
        char secret_message[] = "SECRET";
        int secret_message_len = 6;
        char message[] = "DECOY";
        int message_len = 5;
        memcpy(buffer + sizeof(struct ip) + sizeof(struct tcphdr), &message, message_len);
 
        //Create the IP header
        struct iphdr *ip_header = (struct iphdr *) buffer;
        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htonl(sizeof(struct ip) + sizeof(struct tcphdr));
        ip_header->id = htonl(1);
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0; //Zero it out to iterate over later
        ip_header->saddr = inet_addr(sourceIP); //Send it to ourselves
        ip_header->daddr = inet_addr(destIP);
        ip_header->check = calc_ipv4_check((unsigned short *) ip_header, sizeof(struct ip));
 
        //Create the TCP header
        tcp_header = (struct tcphdr *) (buffer + sizeof(struct ip));
        tcp_header->source = htons(S_PORT);
        tcp_header->dest = htons(D_PORT);
        tcp_header->seq = random();
        tcp_header->urg = 0;
        tcp_header->ack = 0;
        tcp_header->psh = 0;
        tcp_header->rst = 0;
        tcp_header->syn = 0;
        tcp_header->fin = 0;
        tcp_header->ack_seq = 0;
        tcp_header->doff = 5;
        tcp_header->window = 0;
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0; //Set this one later
 
        //Create the raw socket
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(raw_sock < 0)
        {
                printf("Something went wrong with the socket\n");
                printf("Error: %s\n", strerror(errno));
                return 1;
        }
 
        //So that we can fill in our own IP and TCP headers
        int one = 1;
        int opts = setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if(opts < 0)
        {
                printf("Something went wrong with the socket options\n");
                printf("Error: %s\n", strerror(errno));
                return 1;
        }
 
        //To send the packet somewhere
        struct sockaddr_in destAddr;
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(D_PORT);
        destAddr.sin_addr.s_addr = inet_addr(destIP);
 
        //Now loop over the message, split it up and send it in several parts
        int bytes_sent, i;
        for(i = 0; i < secret_message_len; i += 2)
        {
                tcp_header->urg_ptr = secret_message[i] << 8;
                if(i + 2 <= secret_message_len)
                        tcp_header->urg_ptr ^= secret_message[i+1];
 
                //For some reason using ip_header->tot_len gives an error upon sending
                if(bytes_sent = sendto(raw_sock, buffer, (unsigned int) (sizeof(struct ip) + sizeof(struct tcphdr) + message_len), 0, (struct sockaddr *) &destAddr, sizeof(destAddr)) < 0)
                {
                        printf("Error sending packet: %s\n", strerror(errno));
                        return 1;
                }
        }
 
        //We complete the connection with a FIN flag
        ip_header->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
        tcp_header->urg_ptr = 0;
        tcp_header->fin = 1;
        if(bytes_sent = sendto(raw_sock, buffer, (unsigned int) (sizeof(struct ip) + sizeof(struct tcphdr)), 0, (struct sockaddr *) &destAddr, sizeof(destAddr)) < 0)
        {
                printf("Error sending the FIN packet: %s\n", strerror(errno));
                return 1;
        }
 
        return 0;
}
 
//Calculate the ipv4 header checksum
unsigned short calc_ipv4_check(unsigned short *buffPointer, int buffLen)
{
        int i, sum = 0;
        for(i = 0; i < buffLen; i += 2)
        {
                sum += (unsigned short) *(buffPointer + i);
        }
        while(sum > 0xFFFF)
        {
                sum = (sum & 0xFFFF) + (sum >> 16);
        }
 
        sum = ~sum;
        return (unsigned short) sum;
}