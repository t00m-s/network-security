#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct ttl_exceeded_header {
  u_int8_t type;
  u_int8_t code;
  u_int16_t checksum;
  u_int32_t unused;
  struct iphdr internet_header;
  u_int64_t original_datagram_first_64_bits;
} ttl_exceeded_header;

void filter_icmp(char *buffer, size_t buffer_size);

int main(int argc, char *argv[]) {
  struct packet_mreq mr;
  size_t buf_size = 1500;
  char buf[buf_size];
  // 1) Open a raw socket
  // Opens raw socket.
  // AF_PACKET means low-level packet interface
  // SOCK_RAW as the name suggests, raw socket
  // ETH_P_ALL means, just read everything.
  int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (raw_socket == -1) {
    perror("Usage: sudo ./traceroute_server");
    exit(EXIT_FAILURE);
  }
  // 2) Put the NIC in promiscuous mode
  // Adding promiscuous mode to the socket
  mr.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
                 sizeof(mr)) == -1) {
    perror("Error while setting promiscuous mode to socket.");
    close(raw_socket);
    exit(EXIT_FAILURE);
  }
  while (1) {
    // 3) Intercept the ICMP packets that arrive
    // Technically we're intercepting all packets here.
    bzero(buf, buf_size);
    ssize_t data_size = recvfrom(raw_socket, buf, buf_size, 0, NULL, NULL);
    // Either error or 0 read bytes.
    if (data_size <= 0) {
      close(raw_socket);
      exit(EXIT_SUCCESS);
    }
    // 4) filter them for the correct type and code.
    filter_icmp(buf, buf_size);
  }

  // Just in case
  close(raw_socket);
  exit(EXIT_SUCCESS);
}

void filter_icmp(char *buffer, size_t buffer_size) {
  // Filter ICMP packets
  // cat /etc/protocols says that icmp has protocol == 1
  // I trust it.
  struct iphdr *ip_1_header =
      (struct iphdr *)(buffer + sizeof(struct ether_header));
  if (ip_1_header->protocol != 1)
    return;

  // Jumping to the ICMP header
  // ihl is the length of the IP header in 4-bytes
  struct ttl_exceeded_header *icmp_h =
      (struct ttl_exceeded_header *)(buffer + sizeof(struct ether_header) +
                                     (ip_1_header->ihl * 4));
  // Filtering
  if (icmp_h->type != 11)
    return;
  if (icmp_h->code != 0)
    return;

  // From the ICMP packet, you need to read the source IP
  struct in_addr icmp_saddr;
  icmp_saddr.s_addr = icmp_h->internet_header.saddr;
  printf("%s", inet_ntoa(icmp_saddr));

  // From the packet included payload, you need to skip the IP and UDP header,
  // and read the payload
}
