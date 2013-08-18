#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "tcp.h"

#include <arpa/inet.h>

IPv4::IPv4(const struct in_addr& addr) {
  mAddress = (const struct in_addr) addr;
}

IPv4::IPv4(unsigned short v1, unsigned short v2, unsigned short v3, unsigned short v4) {
  uint32_t v = (v1 << 24) + (v2 << 16) + (v3 << 8) + v4;
  mAddress.s_addr = htonl(v);
}

struct in_addr
IPv4::getAddress() const {
  return mAddress;
}

Netmask::Netmask(const IPv4& ip, unsigned short netbits) : mIp(ip), mNetbits(netbits) {
}

IPv4
Netmask::getIp() const {
  return mIp;
}

unsigned short
Netmask::getNetbits() const {
  return mNetbits;
}

bool
Netmask::matches(const IPv4& ip) const {
  uint32_t mask = 0xffffffff << (32 - mNetbits);
  uint32_t networkFilter = ntohl(mIp.getAddress().s_addr) & mask;
  uint32_t networkPacket = ntohl(ip.getAddress().s_addr) & mask;
  return networkFilter == networkPacket;
}

TcpAddress::TcpAddress(const struct in_addr& addr, unsigned short port) {
  string hostname = inet_ntoa((struct in_addr) addr);
  mHostname = hostname;
  mPort = port;
}

TcpAddress::TcpAddress(string hostname, unsigned short port) : mHostname(hostname), mPort(port) {
}

TcpAddress::~TcpAddress() {
}

string
TcpAddress::getHostname() const {
  return mHostname;
}

unsigned short
TcpAddress::getPort() const {
  return mPort;
}

TcpConnection::TcpConnection(const TcpAddress& first, const TcpAddress& second) : mFirst(first), mSecond(second) {
}

TcpConnection::~TcpConnection() {
}

void
TcpConnection::addPacket(bool isIncoming, const Buffer& buffer) {
  if (isIncoming) {
    mInBuffer.append(buffer);
  } else {
    mOutBuffer.append(buffer);
  }
}
