#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
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
#include "tcp.h"
#include "websocket.h"

using namespace std;

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

bool parseAndPrintJson(const char* data, uint16_t len) {
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
    seconds -= baseSeconds;
    microSeconds -= baseMicroSeconds;

    if (microSeconds < 0) {
      microSeconds += 1000000;
      seconds--;
    }
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
    if (data[0] != '{' || !parseAndPrintJson(data, len)) {
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
	int bodyLength = len - (bodySeparator - data + 4);

	if (bodyLength > 0) {
	  const char* body = bodySeparator + 4;

#ifdef ENABLE_JSON
	  if (!parseAndPrintJson(body, bodyLength)) {
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

  while ((frame = ws->getNextFrame()) != nullptr) {
    printPacketInfo(partyName, isIncoming, tv);
    printf("ws %s\n", frame->getSubject().c_str());

    if (!flag_short) {
      printf("\n");

      if (frame->getType() == TEXT) {
	if (frame->getDataLength() > 0) {
#ifdef ENABLE_JSON
	  if (!parseAndPrintJson(frame->getData(), frame->getDataLength())) {
	    printf("    %s (FAILED TO PARSE)\n\n", frame->getData());
	  }
#else /* ENABLE_JSON */
	  printf("    %s\n\n", frame->getData());
#endif /* ENABLE_JSON */
	} else {
	  printf("    Empty frame\n\n");
	}
      } else if (frame->getDataLength() > 0) {
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

void handleTcpPacket(struct timeval tv, const RawIpPacket* ip, const RawTcpPacket* tcp) {
  uint16_t len = ntohs(ip->ip_len) - sizeof(RawIpPacket) - tcp->th_off * 4;

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

void handleIpPacket(struct timeval tv, const RawIpPacket* ip, int /* packet_length */) {
  if (ip->ip_p == IPPROTO_TCP) {
    const RawTcpPacket* tcp = (RawTcpPacket*) (ip + 1);
    handleTcpPacket(tv, ip, tcp);
  } else {
    printf("Unknown IP protocol\n");
  }
}

void dispatcherHandler(u_char * /* temp1 */, const struct pcap_pkthdr *packet_header, const u_char *packet) {
  u_int length = packet_header->len;  /* packet header length  */
  RawEtherPacket* eptr = (RawEtherPacket*) packet;

  if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
    RawIpPacket* ip = (RawIpPacket*) (packet + sizeof(RawEtherPacket));
    handleIpPacket(packet_header->ts, ip, length - sizeof(RawEtherPacket));
  }
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

void printUsage(string programName) {
  fprintf(stderr, "\nUsage: %s [OPTIONS] filename\n\n", programName.c_str());
  fprintf(stderr, "  --short, -s     short output format, no detailed messages\n");
  fprintf(stderr, "  --stopwatch, -0 short output format, no detailed messages\n");
  fprintf(stderr, "  --ws-ports=...  comma separated list of ports used for RFC 6455 compliant web socket connections\n\n");
  exit(1);
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
