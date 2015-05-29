#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
 
#define BUFF_SIZE 65536
#define DEBUG 0 //0 to print result, 1 to print TCP data and urg_ptr, 2 to print IP and TCP packets
#define URG_MSG_SIZE 1025
#define IP "127.0.0.1"
#define PORT 5000
 
void print_ip_header(struct iphdr *ip_header);
void print_tcp_header(struct tcphdr *tcp_header);
void print_ipv4_address(int ip);
void zero_tcp_flags(struct tcphdr *tcp_header);
unsigned short calc_ipv4_check(unsigned short *buffPointer, int buffLen);
 
int main (int argc, char* argv[])
{
        int data_len, i, urg_recv = 0, count = 0;
        struct sockaddr socket_address;
        socklen_t sock_addr_len = sizeof(socket_address);
        unsigned char *buffer = (unsigned char*) malloc(IP_MAXPACKET);
        unsigned char *urg_msg = (unsigned char*) malloc(URG_MSG_SIZE);
        int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
 
        if(raw_socket < 0)
        {
                printf("Something went wrong with the socket\n");
                return 1;
        }
 
        while(1)
        {
                data_len = recvfrom(raw_socket, buffer, IP_MAXPACKET, 0, &socket_address, &sock_addr_len);             
                if(data_len < 0)
                {
                        printf("Could not parse packet\n");
                        continue;
                }
 
                count++;
                if(DEBUG >= 1)
                        printf("--Processing packet number %d--\n", count);
 
                struct iphdr *ip_header = (struct iphdr *) buffer;
                if(ip_header->protocol != IPPROTO_TCP)
                {
                        printf("Packet is not TCP protocol\n");
                        continue;
                }
 
                int th_offset = ip_header->ihl * 4;
                struct tcphdr *tcp_header = (struct tcphdr *) (buffer + th_offset);
                if(tcp_header->dest != htons(PORT))
                {
                        printf("Data was not sent to this port (%d)\n", PORT);
                        continue;
                }
 
                //The FIN flag means the transfer is complete
                if(tcp_header->fin == 1)
                {
                        break;
                }
 
                if(DEBUG >= 2)
                {
                        print_ip_header(ip_header);
                        print_tcp_header(tcp_header);
                }
 
                if(urg_recv < URG_MSG_SIZE - 1) //Since we don't know what packet contains urg_ptr data we have to use all of them
                {
                        urg_msg[urg_recv] = tcp_header->urg_ptr >> 8 & 0xFF;
                        urg_msg[urg_recv+1] = tcp_header->urg_ptr & 0xFF;
                        if(DEBUG >= 1)
                                printf("URG DATA\n%c%c",urg_msg[urg_recv], urg_msg[urg_recv+1]);
                        urg_recv += 2;
                }
 
                int tcp_data_begin = th_offset + tcp_header->doff * 4;
                int tcp_data_size = data_len - tcp_data_begin;
                if(DEBUG >= 1)
                {
                        printf("\nTCP DATA\n");
                        printf("%.*s\n\n", tcp_data_size, (char *) (buffer + tcp_data_begin));
                }
        }
        printf("Transfer completed. Urgent Pointer data received:\n");
        urg_msg[urg_recv] = '\0';
        printf("%s\n", urg_msg);
        close(raw_socket);
        free(urg_msg);
        free(buffer);
        return 0;
}
 
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
 
void zero_tcp_flags(struct tcphdr *tcp_header)
{
        tcp_header->urg = 0;
        tcp_header->ack = 0;
        tcp_header->psh = 0;
        tcp_header->rst = 0;
        tcp_header->syn = 0;
        tcp_header->fin = 0;
        return;
}
 
void print_ip_header(struct iphdr *ip_header)
{
        printf("IP HEADER\n");
        int ip_header_len = ip_header->ihl;
        printf("Version: %u\n", ip_header->version);
        printf("IHL: %u\n", ip_header_len);
        printf("DSCP(ToS): %u\n", ip_header->tos);
        printf("Total length: %u\n", ip_header->tot_len);
        printf("Identification: %u\n", ip_header->id);
        printf("Fragment Offset: %u\n", ip_header->frag_off);
        printf("TTL: %u\n", ip_header->ttl);
        printf("Protocol: %u\n", ip_header->protocol);
        printf("Checksum: %u\n", ip_header->check);
        printf("Source IP: ");
        print_ipv4_address(ip_header->saddr);
        printf("\nDestination IP: ");
        print_ipv4_address(ip_header->daddr);
        printf("\n");
        if(ip_header_len > 5)
        {
                //Print flags
        }
        printf("\n");
        return;
}
 
void print_tcp_header(struct tcphdr *tcp_header)
{
        printf("TCP HEADER\n");
        printf("Source port: %u\n", tcp_header->source);
        printf("Destination port: %u\n", tcp_header->dest);
        printf("Sequence number: %u\n", tcp_header->seq);
        printf("Acknowledgement: %u\n", tcp_header->ack_seq);
        printf("Data offset: %u\n", tcp_header->doff);
        printf("URG: %u\n", tcp_header->urg);
        printf("ACK: %u\n", tcp_header->ack);
        printf("PSH: %u\n", tcp_header->psh);
        printf("RST: %u\n", tcp_header->rst);
        printf("SYN: %u\n", tcp_header->syn);
        printf("FIN: %u\n", tcp_header->fin);
        printf("Window: %u\n", tcp_header->window);
        printf("Checksum: %u\n", tcp_header->check);
        printf("Urgent Pointer: %u\n", tcp_header->urg_ptr);
        printf("\n");
        return;
}
 
void print_ipv4_address(int ip)
{
        printf("%d.%d.%d.%d", ip & 0xFF, (ip >> 8) & 0xFF,
                (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
        return;
}