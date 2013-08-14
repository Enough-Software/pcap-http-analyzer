#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "commparty.h"
#include "tcp.h"
#include "websocket.h"

#include <map>

CommunicationParty::CommunicationParty() : mName(""), mIpAddress("") {
}

CommunicationParty::CommunicationParty(string name, string ipAddress) : mName(name), mIpAddress(ipAddress) {
}

CommunicationParty::~CommunicationParty() {
}

string
CommunicationParty::getName() {
  return mName;
}

void
CommunicationParty::setName(string name) {
  mName = name;
}

string
CommunicationParty::getIpAddress() {
  return mIpAddress;
}

WebSocketParser*
CommunicationParty::getWebSocketParserIncoming() {
  return &mWsIncoming;
}

WebSocketParser*
CommunicationParty::getWebSocketParserOutgoing() {
  return &mWsOutgoing;
}

static map<string, CommunicationParty*> parties;

CommunicationParty*
CommunicationParty::newParty(string ipAddress) {
  string name;
  name = 'A' + parties.size();

  CommunicationParty* party = new CommunicationParty(name, ipAddress);
  return party;
}

CommunicationParty*
CommunicationPartyManager::getParty(string ipAddress) {
  map<string, CommunicationParty*>::iterator it = parties.find(ipAddress);

  if (it != parties.end()) {
    return it->second;
  }

  CommunicationParty* party = CommunicationParty::newParty(ipAddress);
  parties[ipAddress] = party;
  return party;
}

CommunicationParty*
CommunicationPartyManager::getParty(const TcpAddress& addr) {
  string localHostname = addr.getHostname();
  CommunicationParty* party = CommunicationPartyManager::getParty(localHostname);
  return party;
}

void
CommunicationPartyManager::cleanup() {
  map<string, CommunicationParty*>::iterator it;

  for (it = parties.begin(); it != parties.end(); ++it) {
    delete it->second;
  }

  parties.clear();
}
