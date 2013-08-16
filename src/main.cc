#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "args.h"
#include "buffer.h"
#include "commparty.h"
#include "print.h"
#include "tcp.h"
#include "websocket.h"

using namespace std;

static Args sArgs;
static long baseSeconds = 0;
static long baseMicroSeconds = 0;

bool isPacketAllowedByFilters(const RawIpPacket* ip) {
  list<Netmask> filters = sArgs.getFilters();

  for (list<Netmask>::iterator it = filters.begin(); it != filters.end(); it++) {
    if (it->matches(IPv4(ip->ip_dst)) || it->matches(IPv4(ip->ip_src))) {
      return true;
    }
  }

  return false;
}

int isIncomingIpPacket(const RawIpPacket* ip) {
  list<Netmask> filters = sArgs.getFilters();

  for (list<Netmask>::iterator it = filters.begin(); it != filters.end(); it++) {
    if (it->matches(IPv4(ip->ip_dst))) {
      return true;
    }
  }

  return false;
}

#ifdef ENABLE_JSON

bool parseAndPrintJson(const Buffer& buffer) {
  GError* error = NULL;
  bool result = false;
  JsonParser* parser = json_parser_new();
  json_parser_load_from_data(parser, buffer.getData(), buffer.getLength(), &error);

  if (error) {
    g_error_free(error);
  } else {
    result = true;
    JsonNode* root = json_parser_get_root(parser);
    JsonObject* object = json_node_get_object(root);
    printJson(object);
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

  long secondsTotal = tv.tv_sec;
  long microSeconds = tv.tv_usec;

  if (sArgs.useStopwatchFormat()) {
    secondsTotal -= baseSeconds;
    microSeconds -= baseMicroSeconds;

    if (microSeconds < 0) {
      microSeconds += 1000000;
      secondsTotal--;
    }
  }

  int hours = (secondsTotal / 3600) % 24;
  int minutes = (secondsTotal / 60) % 60;
  int seconds = secondsTotal % 60;
  printf("%02d:%02d:%02d.%06ld ", hours, minutes, seconds, microSeconds);
}

void printHttpRequestTitle(const Buffer& buffer) {
  printf("ht ");
  const char* data = buffer.getData();
  const char* eol_char = strchr(data, '\r');

  if (!eol_char) {
    printf("DATA\n");
    return;
  }

  int eol = eol_char - data;
  PRINT_BUFFER(data, eol);
  printf("\n");
}

void handleHttpRequest(const Buffer& buffer) {
  const char* data = buffer.getData();
  int len = buffer.getLength();

  if (len > 10 && strncmp(data, "GET ", 4) == 0) {
    printHttpRequestTitle(buffer);
  } else if (len > 10 && strncmp(data, "POST ", 5) == 0) {
    printHttpRequestTitle(buffer);
  } else if (len > 10 && strncmp(data, "PUT ", 4) == 0) {
    printHttpRequestTitle(buffer);
  } else {
    printf("ht DATA\n");
  }

  if (!sArgs.useShortOutputFormat()) {
    printf("\n");

#ifdef ENABLE_JSON
    if (!parseAndPrintJson(buffer)) {
#endif /* ENABLE_JSON */
      printIndented(4, buffer);

      if (buffer[len - 1] != '\n') {
	printf("\n");
      }
#ifdef ENABLE_JSON
    } else {
      printf("\n");
    }
#endif /* ENABLE_JSON */
  }
}

void handleHttpResponse(const Buffer& buffer) {
  if (buffer.startsWith("HTTP/1.1")) {
    printHttpRequestTitle(buffer);
  } else {
    printf("DATA\n");
  }

  if (!sArgs.useShortOutputFormat()) {
    printf("\n");
    const char* data = buffer.getData();
    int len = buffer.getLength();
    const char* bodySeparator = strstr(data, "\r\n\r\n");

    if (bodySeparator) {
      printIndented(4, data, bodySeparator - data);
      printf("\n");
      int bodyLength = len - (bodySeparator - data + 4);

      if (bodyLength > 0) {
	const char* body = bodySeparator + 4;
        Buffer buffer(body, bodyLength);

#ifdef ENABLE_JSON
	if (!parseAndPrintJson(buffer)) {
#endif /* ENABLE_JSON */
	  printIndented(4, buffer);
#ifdef ENABLE_JSON
	}
#endif /* ENABLE_JSON */
      } else {
	printIndented(4, "Empty body", 12);
      }
    } else {
      PRINT_BUFFER(data, len);
    }

    printf("\n");
  }
}

void printPacketInfo(string partyName, bool isIncoming, struct timeval tv) {
  printf(" %s %s ", partyName.c_str(), isIncoming ? "<<" : ">>");
  printTimestamp(tv);
}

void handleWebsocketNotification(string partyName, bool isIncoming, struct timeval tv, WebSocketParser* ws, const Buffer& data) {
  WebSocketFrame* frame;
  ws->addStreamData(data);

  while ((frame = ws->getNextFrame()) != nullptr) {
    printPacketInfo(partyName, isIncoming, tv);
    printf("ws %s\n", frame->getSubject().c_str());

    if (!sArgs.useShortOutputFormat()) {
      Buffer frameData = frame->getData();

      if (frame->getType() == TEXT) {
	printf("\n");

	if (frameData.getLength() > 0) {
#ifdef ENABLE_JSON
	  if (!parseAndPrintJson(frameData)) {
	    printf("    ");
	    PRINT_BUFFER_1(frameData);
	    printf(" (FAILED TO PARSE)\n");
	  }
#else /* ENABLE_JSON */
	  printf("    ");
	  PRINT_BUFFER_1(frameData);
	  printf("\n");
#endif /* ENABLE_JSON */
	} else {
	  printf("    Empty frame\n");
	}
      } else if (frameData.getLength() > 0) {
	printf("\n");
	printIndented(4, frameData.getData(), frameData.getLength());
      }

      printf("\n");
    }

    delete frame;
  }
}

bool isHttpPort(unsigned short port) {
  set<unsigned short> httpPorts = sArgs.getHttpPorts();
  return httpPorts.find(port) != httpPorts.end();
}

bool isWebSocketPort(unsigned short port) {
  set<unsigned short> webSocketPorts = sArgs.getWebSocketPorts();
  return webSocketPorts.find(port) != webSocketPorts.end();
}

void handleTcpPacket(struct timeval tv, const RawIpPacket* ip, const RawTcpPacket* tcp) {
  uint16_t tcpDataLen = ntohs(ip->ip_len) - sizeof(RawIpPacket) - tcp->th_off * 4;
  Buffer buffer(((const char*) tcp) + tcp->th_off * 4, tcpDataLen);

  if (!isPacketAllowedByFilters(ip)) {
    return;
  }

  TcpAddress src(ip->ip_src, ntohs(tcp->th_sport));
  TcpAddress dest(ip->ip_dst, ntohs(tcp->th_dport));

  if (tcpDataLen == 0) {
    return;
  }

  bool isIncoming = isIncomingIpPacket(ip);
  CommunicationParty* party = CommunicationPartyManager::getParty(isIncoming ? dest : src);
  string partyName = party->getName();

  if (isWebSocketPort(src.getPort()) || isWebSocketPort(dest.getPort())) {
    WebSocketParser* parser = isIncoming ? party->getWebSocketParserIncoming() : party->getWebSocketParserOutgoing();
    handleWebsocketNotification(partyName, isIncoming, tv, parser, buffer);
  } else if (isHttpPort(src.getPort()) || isHttpPort(dest.getPort())) {
    printPacketInfo(partyName, isIncoming, tv);

    if (isIncoming) {
      handleHttpResponse(buffer);
    } else {
      handleHttpRequest(buffer);
    }
  }

  fflush(stdout);
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

int main(int argc, char** argv) {
  sArgs = Args(argc, argv);
  list<string> files = sArgs.getFiles();

  for (list<string>::iterator it = files.begin(); it != files.end(); it++) {
    handlePcapFile(*it);
  }

  CommunicationPartyManager::cleanup();
  return 0;
}
