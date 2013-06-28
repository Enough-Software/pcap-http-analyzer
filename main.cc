#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#ifdef ENABLE_JSON
#include <json/json.h>
#endif /* ENABLE_JSON */

#include "websocket.h"

#define PORT_WEBSOCKET 8089
#define PRINT_HTTP_REQUEST_HEADER 1
#define PRINT_HTTP_REQUEST_BODY 1
#define PRINT_HTTP_RESPONSE_HEADER 1
#define PRINT_HTTP_RESPONSE_BODY 1
#define PRINT_WS_DATA 1

#define PRINT_BUFFER(data, len) {		\
    int buflen = len;				\
    if (buflen < 0) buflen = 0;			\
    char* buffer = (char*) malloc(buflen + 1);	\
    buffer[buflen] = '\0';				\
    strncpy(buffer, data, buflen);			\
    printf("%s", buffer);			\
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

void dispatcherHandler(u_char *, const struct pcap_pkthdr *, const u_char *);

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
  return 0;
}

int is_incoming_ip_packet(const struct nread_ip* ip) {
  u_int32_t local_network = 0x0002A8C0;
  return memcmp(&(ip->ip_src), &local_network, 3) != 0;
}

void printIndent(int indent) {
  for (int index = 0; index < indent; index++) {
    printf(" ");
  }
}

void printIndented(int indent, const char* str, int len) {
  const char* tmp = str;

  while (len > 0) {
    const char* rPos = strchr(tmp, '\r');
    const char* nPos = strchr(tmp, '\n');
    printIndent(indent);

    if (nPos != NULL && (nPos - tmp) < len) {
      if (rPos != NULL && rPos < nPos) {
	PRINT_BUFFER(tmp, rPos - tmp);
      } else {
	PRINT_BUFFER(tmp, nPos - tmp);
      }

      len -= nPos - tmp + 1;
      tmp = nPos + 1;
    } else {
      PRINT_BUFFER(tmp, len);
      len = 0;
    }

    printf("\n");
  }
}

static long baseSeconds = 0;

void printTimestamp(struct timeval tv) {
  if (baseSeconds == 0) {
    baseSeconds = tv.tv_sec;
  }

  long seconds = tv.tv_sec - baseSeconds;
  printf("%02ld:%02ld:%02ld.%06ld ", seconds / 3600, (seconds / 60) % 60, seconds % 60, tv.tv_usec);
}

#ifdef ENABLE_JSON

void print_json_object(json_object* jobj, int indent) {
  printIndent(indent);
  printf("{\n");

  /*
  struct json_object_iterator it = json_object_iter_begin(jobj);
  struct json_object_iterator itEnd = json_object_iter_end(jobj);

  while (!json_object_iter_equal(&it, &itEnd)) {
    const char* keyName = json_object_iter_peek_name(&it);
    print_indent(indent + 2);
    printf("%s:\n", keyName);

    json_object_iter_next(&it);
  }
  */

  /*
  for (int index = 0; index < json_object_array_length(jobj), index++) {
    const json_object* = json_object_array_get_idx(jobj, index);
  }
  */

  printIndent(indent);
  printf("}\n");
}

#endif /* ENABLE_JSON */

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

static WebSocketParser* webSockets[10];
static int num_known_parties = 0;
static char* known_parties[10];

int getPartyIndex(const struct in_addr *ip_addr) {
  char* ip_name = inet_ntoa((struct in_addr) *ip_addr);
  int foundIndex = -1;

  for (int index = 0; index < num_known_parties; index++) {
    if (strcmp(ip_name, known_parties[index]) == 0) {
      foundIndex = index;
      break;
    }
  }

  if (foundIndex == -1 && num_known_parties < 10) {
    int len = strlen(ip_name);
    char* tmp_name = (char*) malloc(len + 1);
    strncpy(tmp_name, ip_name, len);
    tmp_name[len] = '\0';
    known_parties[num_known_parties] = tmp_name;
    webSockets[num_known_parties] = new WebSocketParser();
    foundIndex = num_known_parties;
    num_known_parties++;
  }

  return foundIndex;
}

const char* getPartyName(int partyIndex) {
  char* party_name = (char*) malloc(2);
  party_name[0] = 'A' + partyIndex;
  party_name[1] = '\0';
  return party_name;
}

void handleWebsocketNotification(struct timeval tv, int partyIndex, const char* data, uint16_t len) {
  WebSocketFrame* frame;
  WebSocketParser* ws = webSockets[partyIndex];
  ws->addStreamData(data, len);

  while ((frame = ws->getNextFrame()) != NULL) {
    printf(" %s << ", getPartyName(partyIndex));
    printTimestamp(tv);
    printf("WS %s\n\n", frame->getSummary());

    if (PRINT_WS_DATA) {
      printf("    %s\n\n", frame->getData());

#ifdef ENABLE_JSON
      enum json_tokener_error jerr;
      json_tokener* tok = json_tokener_new();
      json_object* jobj = json_tokener_parse_ex(tok, data + 4, len - 4);

      if ((jerr = json_tokener_get_error(tok)) == json_tokener_success) {
	print_json_object(jobj, 4);
      } else {
	print_packet_data(data + 4, len - 4);
      }
#endif /* ENABLE_JSON */
    }
  }
}

void handleTcpPacket(struct timeval tv, const struct nread_ip* ip, const struct nread_tcp* tcp) {
  uint16_t len = ntohs(ip->ip_len) - sizeof(struct nread_ip) - tcp->th_off * 4;
  const char* data = ((const char*) tcp) + tcp->th_off * 4;

  if (len == 0) {
    return;
  }

  const struct in_addr* ip_addr;

  if (is_incoming_ip_packet(ip)) {
    ip_addr = &(ip->ip_dst);
  } else {
    ip_addr = &(ip->ip_src);
  }

  int partyIndex = getPartyIndex(ip_addr);

  if (is_incoming_ip_packet(ip)) {
    if (ntohs(tcp->th_sport) == PORT_WEBSOCKET) {
      handleWebsocketNotification(tv, partyIndex, data, len);
    } else {
      printf(" %s << ", getPartyName(partyIndex));
      printTimestamp(tv);
      handleHttpResponse(data, len);
    }
  } else {
    printf(" %s >> ", getPartyName(partyIndex));
    printTimestamp(tv);

    if (ntohs(tcp->th_dport) == PORT_WEBSOCKET) {
      printf("WS ");
    }

    handleHttpRequest(data, len);
  }
}

void handleIpPacket(struct timeval tv, const struct nread_ip* ip, int /* packet_length */) {
  if (ip->ip_p == IPPROTO_TCP) {
    const struct nread_tcp* tcp = (struct nread_tcp*)(ip + 1);
    handleTcpPacket(tv, ip, tcp);
  } else {
    printf("Unknown IP protocol\n");
  }
}

void dispatcherHandler(u_char * /* temp1 */, const struct pcap_pkthdr *packet_header, const u_char *packet) {
  u_int length = packet_header->len;  /* packet header length  */
  struct ether_header *eptr = (struct ether_header *) (packet);

  if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
    struct nread_ip* ip;

    ip = (struct nread_ip*) (packet + sizeof(struct ether_header));
    handleIpPacket(packet_header->ts, ip, length - sizeof(struct ether_header));
  }
}

