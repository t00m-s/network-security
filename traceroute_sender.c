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


struct udpheader
{
    u_int16_t udp_sport;
    u_int16_t udp_dport;
    u_int16_t udp_ulen;
    u_int16_t udp_sum;
};

struct ipheader
{
    unsigned char       iph_ihl:4,
                        iph_ver:4;
    unsigned char       iph_tos;
    unsigned short int  iph_len;
    unsigned short int  iph_ident;
    unsigned short int  iph_flag:3,
                        iph_offset:13;
    unsigned char       iph_ttl;
    unsigned char       iph_protocol;
    unsigned short int  iph_chksum;
    struct in_addr      iph_sourceip;
    struct in_addr      iph_destip;
};

struct ipheader* fill_ip_header(char* buffer, char* s_addr, unsigned char ttl, int packet_size)
{
    struct ipheader* ip = (struct ipheader*) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = ttl;      // Take the ttl as parameter
    // Could this be wrong?
    ip->iph_destip.s_addr = inet_addr("127.0.0.1");
    ip->iph_sourceip.s_addr = inet_addr(s_addr);
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_len = htons(sizeof(struct ipheader) + packet_size);
    
    return ip;
}

struct udpheader* fill_udp_header(char* buffer, int msg_len)
{
    struct udpheader* udp = (struct udpheader*) buffer;
    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(9090);
    udp->udp_ulen = htons(sizeof(struct udpheader) + msg_len);
    // We don't care about calculating the checksum
    udp->udp_sum = 0;
    
    return udp;
}


int main(int argc, char** argv) {
    char buffer[1500];
    char* src_ip = "8.8.8.8";
    struct sockaddr_in dest;
    char* message = "Lmao\n";
    int msg_len = strlen(message);
    int iph_len = sizeof(struct ipheader);
    int udp_len = sizeof(struct udpheader);

    int total_length = iph_len + udp_len + msg_len;

    if (argc > 1) {
        src_ip = argv[1];
    } else {
        printf("Usage: traceroute_sender <ip_addr>\n");
        exit(1);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Please run as root\n");
        exit(1);
    }

    struct ipheader* ip = fill_ip_header(buffer, src_ip, 10, udp_len + msg_len);
                    // Skip IP header
    fill_udp_header(buffer + iph_len, msg_len);
            // Write the message after the headers
    strncpy(buffer + iph_len + udp_len, message, msg_len);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    dest.sin_family = AF_INET;
    dest.sin_addr = ip->iph_destip;
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr*) &dest, sizeof(dest));
}
