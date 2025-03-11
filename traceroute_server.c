#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  u_int8_t type;
  u_int8_t code;
  u_int16_t checksum;
  u_int32_t unused;
  struct iphdr internet_header;
  u_int64_t original_datagram_first_64_bits;
} icmp_header;

void filter_icmp(char *buffer, size_t buffer_size);

int main(int argc, char *argv[]) {
  struct packet_mreq mr;
  size_t buf_size = 1500;
  char buf[buf_size];
  // 1) Open a raw socket
  // Opens raw socket for all kinds of packets.
  int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  // 2) Put the NIC in promiscuous mode
  // Setting the socket in promiscuous mode
  mr.mr_type = PACKET_MR_PROMISC;
  setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
  if (raw_socket == -1) {
    perror("Usage: sudo ./traceroute_server");
    exit(EXIT_FAILURE);
  }
  while (1) {
    // 3) Intercept the ICMP packets that arrive
    // Technically we're intercepting all packets here.
    bzero(buf, buf_size);
    size_t data_size = recvfrom(raw_socket, buf, buf_size, 0, NULL, NULL);
    if (data_size == 0) {
      goto cleanup;
    }
    // 4) filter them for the correct type and code.
    filter_icmp(buf, buf_size);
  }

  // Nic cleanup
  // Alvise Favero ~ 11/03/2025: Scrivi un commento in cui tu te ne assumi la
  // responsabilità.
  // Tommaso Soncin ~ 11/03/2025: sto veramente usando goto e mi assumo la
  // responsabilità di sto scempio.
cleanup:
  close(raw_socket);
  exit(EXIT_SUCCESS);
}

void filter_icmp(char *buffer, size_t buffer_size) {
  struct iphdr *ip_header =
      (struct iphdr *)(buffer + sizeof(struct ether_header));
  if (ip_header->protocol != 11)
    return;
}
