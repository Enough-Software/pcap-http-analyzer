#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#define PORT_WEBSOCKET 8089
#define PRINT_DATA 1

#define PRINT_BUFFER(data, len) {		\
    if (len < 0) len = 0;			\
    char* buffer = (char*) malloc(len + 1);	\
    buffer[len] = '\0';				\
    strncpy(buffer, data, len);			\
    printf("%s", buffer);			\
    free(buffer);				\
}

#define PRINTLN_BUFFER(data, len) {		\
    if (len < 0) len = 0;			\
    char* buffer = (char*) malloc(len + 1);	\
    buffer[len] = '\0';				\
    strncpy(buffer, data, len);			\
    printf("%s\n", buffer);			\
    free(buffer);				\
}

typedef u_int32_t tcp_seq;

struct nread_ip {
  u_int8_t        ip_vhl;          /* header length, version    */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
  u_int8_t        ip_tos;          /* type of service           */
  u_int16_t       ip_len;          /* total length              */
  u_int16_t       ip_id;           /* identification            */
  u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
  u_int8_t        ip_ttl;          /* time to live              */
  u_int8_t        ip_p;            /* protocol                  */
  u_int16_t       ip_sum;          /* checksum                  */
  struct  in_addr ip_src;
  struct  in_addr ip_dst;  /* source and dest address   */
};

struct nread_tcp {
  u_short th_sport; /* source port            */
  u_short th_dport; /* destination port       */
  tcp_seq th_seq;   /* sequence number        */
  tcp_seq th_ack;   /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int th_x2:4,    /* (unused)    */
  th_off:4;         /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
  u_int th_off:4,   /* data offset */
  th_x2:4;          /* (unused)    */
#endif
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

//char* default_filename = "/home/mkoch/test.pcapng";
const char* default_filename = "/home/mkoch/acceptence-bug-A-party.pcapng";

int main(int argc, char** argv) {
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (argc != 2) {
    fprintf(stderr, "\nUsage: %s filename", argv[0]);
    return -1;
  }

//  if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL) {
  if ((fp = pcap_open_offline(default_filename, errbuf)) == NULL) {
    fprintf(stderr, "\bError opening dump file\n");
    return -1;
  }

  pcap_loop(fp, 0, dispatcher_handler, NULL);
  return 0;
}

int is_incoming_ip_packet(const struct nread_ip* ip) {
  u_int32_t local_network = 0x0002A8C0;
  return memcmp(&(ip->ip_src), &local_network, 3) != 0;
}

void print_packet_data(const char* data, int len) {
    if (PRINT_DATA == 0) {
        return;
    }

    PRINTLN_BUFFER(data, len);
}

void print_http_request(const char* data, int /* len */) {
  const char* eol_char = strchr(data, '\r');

  if (!eol_char) {
    printf("DATA\n");
    return;
  }

  int eol = eol_char - data;
  PRINTLN_BUFFER(data, eol);
}

void handle_http_request(const char* data, int len) {
    if (len > 10 && strncmp(data, "GET ", 4) == 0) {
        print_http_request(data, len);
    } else if (len > 10 && strncmp(data, "POST ", 5) == 0) {
        print_http_request(data, len);
    } else if (len > 10 && strncmp(data, "PUT ", 4) == 0) {
        print_http_request(data, len);
    } else { 
        printf("DATA\n");
    }

    print_packet_data(data, len);
}

void handle_http_response(const char* data, int len) {
  if (len > 10 && strncmp(data, "HTTP/1.1", 8) == 0) {
    print_http_request(data, len);
  } else {
    printf("DATA\n");
  }

  print_packet_data(data, len);
}

void handle_websocket_notification(const char* data, int len) {
  const char* p_type = strstr(data, "\"type\":\"");

  if (p_type) {
    const char* p_type_str = p_type + 8;
    const char* p_type_str_end = strchr(p_type_str, '\"');

    if (p_type_str_end) {
      int len = p_type_str_end - p_type_str;
      PRINT_BUFFER(p_type_str, len);
    }
  }

  printf("\n");
  print_packet_data(data + 4, len - 4);
}

void handle_tcp_packet(const struct nread_ip* ip, const struct nread_tcp* tcp) {
  int len = ntohs(ip->ip_len) - sizeof(struct nread_ip) - tcp->th_off * 4;
  const char* data = ((const char*) tcp) + tcp->th_off * 4;

  if (len == 0) {
//    printf(" empty\n");
    return;
  }

  if (is_incoming_ip_packet(ip)) {
    if (ntohs(tcp->th_sport) == PORT_WEBSOCKET) {
      printf(" << WS");
      handle_websocket_notification(data, len);
    } else {
      printf(" <  ");
      handle_http_response(data, len);
    }
  } else {
    printf(" >  ");
    handle_http_request(data, len);
  }

  if (PRINT_DATA) {
    printf("\n");
  }
}

void handle_ip_packet(const struct nread_ip* ip, int /* packet_length */) {
  if (ip->ip_p == IPPROTO_TCP) {
    const struct nread_tcp* tcp = (struct nread_tcp*)(ip + 1);    
    handle_tcp_packet(ip, tcp);
  } else {
    printf("Unknown IP protocol\n");
  }
}

void dispatcher_handler(u_char * /* temp1 */, const struct pcap_pkthdr *packet_header, const u_char *packet) {
  u_int length = packet_header->len;  /* packet header length  */
  struct ether_header *eptr = (struct ether_header *) (packet);

  if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
    struct nread_ip* ip;

    ip = (struct nread_ip*) (packet + sizeof(struct ether_header));
    handle_ip_packet(ip, length - sizeof(struct ether_header));
  }
}

