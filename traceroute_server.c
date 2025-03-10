#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef struct {
  u_int8_t type;
  u_int8_t code;
  u_int16_t checksum;
  u_int32_t unused;
  struct iphdr internet_header;
  u_int64_t original_datagram_first_64_bits;
} icmp_header;
int main(void) {
  int raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
  if (raw_socket == -1) {
    printf("Usage: sudo ./traceroute_server");
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
}
