#ifndef __COMMUNICATION_PARTY_H__
#define __COMMUNICATION_PARTY_H__

#include "websocket.h"

#include <netinet/in.h>

using namespace std;

class CommunicationParty {
 public:
  CommunicationParty();
  CommunicationParty(string name, string ipAddress);
  virtual ~CommunicationParty();

  string getName();
  void setName(string name);

  string getIpAddress();

  WebSocketParser* getWebSocketParserIncoming();
  WebSocketParser* getWebSocketParserOutgoing();

  static CommunicationParty* newParty(string ipAddress);

 private:
  string mName;
  string mIpAddress;
  WebSocketParser mWsIncoming;
  WebSocketParser mWsOutgoing;
};

class CommunicationPartyManager {
 public:
  static void cleanup();

  static CommunicationParty* getParty(string ipAddress);
  static CommunicationParty* getParty(const struct in_addr& addr);
};

#endif /* __COMMUNICATION_PARTY_H__ */
