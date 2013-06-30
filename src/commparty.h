#ifndef __COMMUNICATION_PARTY_H__
#define __COMMUNICATION_PARTY_H__

#include <string>

using namespace std;

class WebSocketParser;

class CommunicationParty {
 private:
CommunicationParty(string name, string ipAddress);

 public:
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
  WebSocketParser* mWsIncoming;
  WebSocketParser* mWsOutgoing;
};

class CommunicationPartyManager {
 public:
  static CommunicationParty* getParty(string ipAddress);
};

#endif /* __COMMUNICATION_PARTY_H__ */
