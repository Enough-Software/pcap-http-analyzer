#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "commparty.h"
#include "websocket.h"

#include <map>

CommunicationParty::CommunicationParty(string name, string ipAddress) : mName(name), mIpAddress(ipAddress) {
  mWsIncoming = new WebSocketParser();
  mWsOutgoing = new WebSocketParser();
}

CommunicationParty::~CommunicationParty() {
  delete mWsIncoming;
  delete mWsOutgoing;
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
  return mWsIncoming;
}

WebSocketParser*
CommunicationParty::getWebSocketParserOutgoing() {
  return mWsOutgoing;
}

static unsigned int nextPartyIndex = 0;

CommunicationParty*
CommunicationParty::newParty(string ipAddress) {
  string name;
  name = 'A' + nextPartyIndex;
  nextPartyIndex++;

  CommunicationParty* party = new CommunicationParty(name, ipAddress);
  return party;
}

static map<string, CommunicationParty*> parties;

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
