#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <set>
#include <sstream>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "commparty.h"
#include "print.h"
#include "websocket.h"

using namespace std;

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

static int flag_short = 0;
static int flag_stopwatch = 0;
static long baseSeconds = 0;
static long baseMicroSeconds = 0;
static set<unsigned short> webSocketPorts;

int isIncomingIpPacket(const struct nread_ip* ip) {
  u_int32_t localNetwork = 0x0000A8C0;
  return memcmp(&(ip->ip_src), &localNetwork, 2) != 0;
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

  long seconds = tv.tv_sec;
  long microSeconds = tv.tv_usec;

  if (flag_stopwatch) {
    if (microSeconds < 0) {
      microSeconds += 1000000;
      seconds--;
    }

    seconds -= baseSeconds;
    microSeconds -= baseMicroSeconds;
  }

  printf("%02ld:%02ld:%02ld.%06ld ", (seconds / 3600) % 24, (seconds / 60) % 60, seconds % 60, microSeconds);
}

void printHttpRequestTitle(const char* data, int /* len */) {
  printf("ht ");
  const char* eol_char = strchr(data, '\r');

  if (!eol_char) {
    printf("DATA\n");
    return;
  }

  int eol = eol_char - data;
  PRINT_BUFFER(data, eol);
  printf("\n");
}

void handleHttpRequest(const char* data, int len) {
  if (len > 10 && strncmp(data, "GET ", 4) == 0) {
    printHttpRequestTitle(data, len);
  } else if (len > 10 && strncmp(data, "POST ", 5) == 0) {
    printHttpRequestTitle(data, len);
  } else if (len > 10 && strncmp(data, "PUT ", 4) == 0) {
    printHttpRequestTitle(data, len);
  } else {
    printf("ht DATA\n");
  }

  if (!flag_short) {
    printf("\n");

#ifdef ENABLE_JSON
    if (data[0] != '{' || !parseJson(data, len)) {
#endif /* ENABLE_JSON */
      printIndented(4, data, len);

      if (data[len - 1] != '\n') {
	printf("\n");
      }
#ifdef ENABLE_JSON
    }
#endif /* ENABLE_JSON */
  }
}

void handleHttpResponse(const char* data, int len) {
  if (len > 10 && strncmp(data, "HTTP/1.1", 8) == 0) {
    printHttpRequestTitle(data, len);
  } else {
    printf("DATA\n");
  }

  if (!flag_short) {
    printf("\n");
    const char* bodySeparator = strstr(data, "\r\n\r\n");

    if (bodySeparator) {
      if (!flag_short) {
	printIndented(4, data, bodySeparator - data);
	printf("\n");
      }

      int bodyLength = len - (bodySeparator - data + 4);

      if (!flag_short) {
	if (bodyLength > 0) {
	  const char* body = bodySeparator + 4;

#ifdef ENABLE_JSON
	  if (!parseJson(body, bodyLength)) {
#endif /* ENABLE_JSON */
	    printIndented(4, body, bodyLength);
	    printf("\n");
#ifdef ENABLE_JSON
	  }
#endif /* ENABLE_JSON */
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

void printPacketInfo(string partyName, bool isIncoming, struct timeval tv) {
  printf(" %s %s ", partyName.c_str(), isIncoming ? "<<" : ">>");
  printTimestamp(tv);
}

void handleWebsocketNotification(string partyName, bool isIncoming, struct timeval tv, WebSocketParser* ws, const char* data, uint16_t len) {
  WebSocketFrame* frame;
  ws->addStreamData(data, len);

  while ((frame = ws->getNextFrame()) != NULL) {
    printPacketInfo(partyName, isIncoming, tv);
    printf("ws %s\n", frame->getSubject().c_str());

    if (!flag_short) {
      printf("\n");

      if (frame->getType() == TEXT) {
	if (frame->getDataLength() > 0) {
#ifdef ENABLE_JSON
	  if (!parseJson(frame->getData(), frame->getDataLength())) {
	    printf("    %s (FAILED TO PARSE)\n\n", frame->getData());
	  }
#else /* ENABLE_JSON */
	  printf("    %s\n\n", frame->getData());
#endif /* ENABLE_JSON */
	} else {
	  printf("    Empty frame\n\n");
	}
      } else {
	printIndented(4, frame->getData(), frame->getDataLength());
	printf("\n");
      }
    }

    delete frame;
  }
}

void parseWebSocketPorts(string webSocketList) {
  webSocketPorts.clear();

  string item;
  stringstream ss(webSocketList);

  while (getline(ss, item, ',')) {
    unsigned short port = strtoul(item.c_str(), NULL, 0);
    webSocketPorts.insert(port);
  }
}

bool isWebSocket(unsigned short port) {
  return webSocketPorts.find(port) != webSocketPorts.end();
}

void handleTcpPacket(struct timeval tv, const struct nread_ip* ip, const struct nread_tcp* tcp) {
  uint16_t len = ntohs(ip->ip_len) - sizeof(struct nread_ip) - tcp->th_off * 4;

  if (len == 0) {
    return;
  }

  const struct in_addr* ipAddr = isIncomingIpPacket(ip) ? &(ip->ip_dst) : &(ip->ip_src);
  string localHostname = inet_ntoa((struct in_addr) *ipAddr);
  CommunicationParty* party = CommunicationPartyManager::getParty(localHostname);
  const char* data = ((const char*) tcp) + tcp->th_off * 4;

  if (isIncomingIpPacket(ip)) {
    if (isWebSocket(ntohs(tcp->th_sport))) {
      handleWebsocketNotification(party->getName(), true, tv, party->getWebSocketParserIncoming(), data, len);
    } else {
      printPacketInfo(party->getName(), true, tv);
      handleHttpResponse(data, len);
    }
  } else {
    if (isWebSocket(ntohs(tcp->th_dport))) {
      handleWebsocketNotification(party->getName(), false, tv, party->getWebSocketParserOutgoing(), data, len);
    } else {
      printPacketInfo(party->getName(), false, tv);
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

void printUsage(string programName) {
  fprintf(stderr, "\nUsage: %s [OPTIONS] filename\n\n", programName.c_str());
  fprintf(stderr, "  --short, -s     short output format, no detailed messages\n");
  fprintf(stderr, "  --stopwatch, -0 short output format, no detailed messages\n");
  fprintf(stderr, "  --ws-ports=...  comma separated list of ports used for RFC 6455 compliant web socket connections\n\n");
  exit(1);
}

void handlePcapFile(string filename) {
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];

  if ((fp = pcap_open_offline(filename.c_str(), errbuf)) == NULL) {
    fprintf(stderr, "Error opening dump file: %s\n", filename.c_str());
    exit(1);
  }

  pcap_loop(fp, 0, dispatcherHandler, NULL);
  pcap_close(fp);
}

int main(int argc, char** argv) {
  static struct option long_options[] = {
    { "short",     no_argument,       0, 's'},
    { "stopwatch", no_argument,       0, '0'},
    { "ws-ports",  required_argument, 0, 'w'},
    { 0, 0, 0, 0 }
  };

  while (1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "sw:0", long_options, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
    case 's':
      flag_short = 1;
      break;

    case 'w':
      parseWebSocketPorts(optarg);
      break;

    case '0':
      flag_stopwatch = 1;
      break;

    default:
      printUsage(argv[0]);
      break;
    }
  }

  if (optind < argc) {
    while (optind < argc) {
      handlePcapFile(argv[optind++]);
    }
  } else {
    printUsage(argv[0]);
  }

  return 0;
}
