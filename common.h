#include <stdlib.h>
#include <netinet/in.h>

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
