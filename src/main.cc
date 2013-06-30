#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "commparty.h"
#include "print.h"
#include "websocket.h"

#define PORT_WEBSOCKET 8089
#define PRINT_HTTP_REQUEST_HEADER 1
#define PRINT_HTTP_REQUEST_BODY 1
#define PRINT_HTTP_RESPONSE_HEADER 1
#define PRINT_HTTP_RESPONSE_BODY 1
#define PRINT_WS_DATA 1

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

static long baseSeconds = 0;
static long baseMicroSeconds = 0;

int is_incoming_ip_packet(const struct nread_ip* ip) {
  u_int32_t local_network = 0x0002A8C0;
  return memcmp(&(ip->ip_src), &local_network, 3) != 0;
}

#ifdef ENABLE_JSON

bool parseJson(const char* data, uint16_t len) {
  GError* error = NULL;
  bool result = false;
  JsonParser* parser = json_parser_new();
  json_parser_load_from_data(parser, data, len, &error);

  if (error) {
    g_error_free(error);
  } else {
    result = true;
    JsonNode* root = json_parser_get_root(parser);
    printJson(json_node_get_object(root));
  }

  g_object_unref(parser);
  return result;
}

#endif /* ENABLE_JSON */

void printTimestamp(struct timeval tv) {
  if (baseSeconds == 0) {
    baseSeconds = tv.tv_sec;
    baseMicroSeconds = tv.tv_usec;
  }

  long seconds = tv.tv_sec - baseSeconds;
  long microSeconds = tv.tv_usec - baseMicroSeconds;

  if (microSeconds < 0) {
    microSeconds += 1000000;
    seconds--;
  }

  printf("%02ld:%02ld:%02ld.%06ld ", (seconds / 3600) % 24, (seconds / 60) % 60, seconds % 60, microSeconds);
}

void printHttpRequestTitle(const char* data, int /* len */) {
  const char* eol_char = strchr(data, '\r');

  if (!eol_char) {
    printf("DATA\n\n");
    return;
  }

  int eol = eol_char - data;
  PRINT_BUFFER(data, eol);
  printf("\n\n");
}

void handleHttpRequest(const char* data, int len) {
  if (len > 10 && strncmp(data, "GET ", 4) == 0) {
    printHttpRequestTitle(data, len);
  } else if (len > 10 && strncmp(data, "POST ", 5) == 0) {
    printHttpRequestTitle(data, len);
  } else if (len > 10 && strncmp(data, "PUT ", 4) == 0) {
    printHttpRequestTitle(data, len);
  } else {
    printf("DATA\n\n");
  }

  if (PRINT_HTTP_REQUEST_HEADER) {
    printIndented(4, data, len);

    if (data[len - 1] != '\n') {
      printf("\n");
    }
  }
}

void handleHttpResponse(const char* data, int len) {
  if (len > 10 && strncmp(data, "HTTP/1.1", 8) == 0) {
    printHttpRequestTitle(data, len);
  } else {
    printf("DATA\n\n");
  }

  if (PRINT_HTTP_RESPONSE_HEADER || PRINT_HTTP_RESPONSE_BODY) {
    const char* bodySeparator = strstr(data, "\r\n\r\n");

    if (bodySeparator) {
      if (PRINT_HTTP_RESPONSE_HEADER) {
	printIndented(4, data, bodySeparator - data);
	printf("\n");
      }

      int bodyLength = len - (bodySeparator - data + 4);

      if (PRINT_HTTP_RESPONSE_BODY) {
	if (bodyLength > 0) {
	  printIndented(4, bodySeparator + 4, bodyLength);
	  printf("\n");
	} else {
	  printIndented(4, "Empty body\n\n", 12);
	}
      }
    } else {
      PRINT_BUFFER(data, len);
      printf("\n");
    }
  }
}

void handleWebsocketNotification(WebSocketParser* ws, const char* data, uint16_t len) {
  WebSocketFrame* frame;
  ws->addStreamData(data, len);

  while ((frame = ws->getNextFrame()) != NULL) {
    printf("WS %s\n\n", frame->getSubject().c_str());

    if (PRINT_WS_DATA && frame->getType() == TEXT) {
      if (frame->getDataLength() > 0) {
#ifdef ENABLE_JSON
	if (!parseJson(data + 4, len - 4)) {
#endif /* ENABLE_JSON */
	  printf("    %s\n\n", frame->getData());
#ifdef ENABLE_JSON
	}
#endif /* ENABLE_JSON */
      } else {
	printf("    Empty frame\n\n");
      }
    }

    delete frame;
  }
}

void handleTcpPacket(struct timeval tv, const struct nread_ip* ip, const struct nread_tcp* tcp) {
  uint16_t len = ntohs(ip->ip_len) - sizeof(struct nread_ip) - tcp->th_off * 4;

  if (len == 0) {
    return;
  }

  const struct in_addr* ip_addr;

  if (is_incoming_ip_packet(ip)) {
    ip_addr = &(ip->ip_dst);
  } else {
    ip_addr = &(ip->ip_src);
  }

  string localHostname = inet_ntoa((struct in_addr) *ip_addr);
  CommunicationParty* party = CommunicationPartyManager::getParty(localHostname);
  const char* data = ((const char*) tcp) + tcp->th_off * 4;

  if (is_incoming_ip_packet(ip)) {
    printf(" %s << ", party->getName().c_str());
    printTimestamp(tv);

    if (ntohs(tcp->th_sport) == PORT_WEBSOCKET) {
      handleWebsocketNotification(party->getWebSocketParserIncoming(), data, len);
    } else {
      handleHttpResponse(data, len);
    }
  } else {
    printf(" %s >> ", party->getName().c_str());
    printTimestamp(tv);

    if (ntohs(tcp->th_dport) == PORT_WEBSOCKET) {
      handleWebsocketNotification(party->getWebSocketParserOutgoing(), data, len);
    } else {
      handleHttpRequest(data, len);
    }
  }
}

void handleIpPacket(struct timeval tv, const struct nread_ip* ip, int /* packet_length */) {
  if (ip->ip_p == IPPROTO_TCP) {
    const struct nread_tcp* tcp = (struct nread_tcp*) (ip + 1);
    handleTcpPacket(tv, ip, tcp);
  } else {
    printf("Unknown IP protocol\n");
  }
}

void dispatcherHandler(u_char * /* temp1 */, const struct pcap_pkthdr *packet_header, const u_char *packet) {
  u_int length = packet_header->len;  /* packet header length  */
  struct ether_header *eptr = (struct ether_header *) (packet);

  if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
    struct nread_ip* ip;

    ip = (struct nread_ip*) (packet + sizeof(struct ether_header));
    handleIpPacket(packet_header->ts, ip, length - sizeof(struct ether_header));
  }
}

int main(int argc, char** argv) {
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (argc != 2) {
    fprintf(stderr, "\nUsage: %s filename", argv[0]);
    return -1;
  }

  if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL) {
    fprintf(stderr, "\bError opening dump file\n");
    return -1;
  }

  pcap_loop(fp, 0, dispatcherHandler, NULL);
  pcap_close(fp);
  return 0;
}
