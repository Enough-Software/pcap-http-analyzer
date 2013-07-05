#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "tcp.h"

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
