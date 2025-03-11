/* Socket */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
/* Tipi della rete, ad esempio AF_INET */
#include <sys/types.h>
/* Struct per l'indirizzo */
#include <netinet/in.h>
/* Funzione per convertire gli indirizzi*/
#include <arpa/inet.h>
/* Chiusura del file descriptor dello stream */
#include <unistd.h>

#include "common.h"

#define MAX_ROUTE_LENGTH 64


struct ipheader* fill_ip_header(char* buffer, char* src_ip, char* dst_ip, unsigned char ttl, int packet_size)
{
    struct ipheader* ip = (struct ipheader*) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = ttl;      /* Take the ttl as parameter */
    ip->iph_sourceip.s_addr = inet_addr(src_ip);
    ip->iph_destip.s_addr = inet_addr(dst_ip);
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_len = htons(sizeof(struct ipheader) + packet_size);
    
    return ip;
}

struct udpheader* fill_udp_header(char* buffer, unsigned short dst_port, int msg_len)
{
    struct udpheader* udp = (struct udpheader*) buffer;
    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(dst_port);
    udp->udp_ulen = htons(sizeof(struct udpheader) + msg_len);
    /* We don't care about calculating the checksum */
    udp->udp_sum = 0;
    
    return udp;
}


int main(int argc, char** argv) {
    char buffer[1500];
    char* src_ip;
    char* dst_ip;
    struct sockaddr_in dest;
    int iph_len = sizeof(struct ipheader);
    int udp_len = sizeof(struct udpheader);
    u_int8_t ttl;
    int msg_len = sizeof(u_int8_t);
    struct ipheader* ip_packet;
    int total_length = iph_len + udp_len + msg_len;

    if (argc > 2) {
        src_ip = argv[1];
        dst_ip = argv[2];
    } else {
        printf("Usage: sudo traceroute_sender <source_ip> <destination_ip>\n");
        exit(1);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Please run as root\n");
        exit(1);
    }

    ip_packet = fill_ip_header(buffer, src_ip, dst_ip, ttl, udp_len + msg_len);
    fill_udp_header(buffer + iph_len, 53, msg_len);

    /* Create the socket */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    dest.sin_family = AF_INET;
    dest.sin_addr = ip_packet->iph_destip;

    for (ttl = 1; ttl < MAX_ROUTE_LENGTH; ttl++) {
        /* Set ttl */
        ip_packet->iph_ttl = ttl;
        /* Set payload to ttl current value */
        strncpy(buffer + iph_len + udp_len, (char*) &ttl, msg_len);
        sendto(sock, ip_packet, ntohs(ip_packet->iph_len), 0, (struct sockaddr*) &dest, sizeof(dest));
    }
    
    if (close(sock)) {
        fprintf(stderr, "Error closing socket\n");
        exit(1);
    }
}
