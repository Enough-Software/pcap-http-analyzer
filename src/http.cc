#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "http.h"

HttpConnection::HttpConnection() {
}

HttpConnection::~HttpConnection() {
}

bool
HttpConnection::addPacket(const Buffer& data) {
  return false;
}
