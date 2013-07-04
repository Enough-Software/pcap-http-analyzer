#ifndef __HTTP_H__
#define __HTTP_H__

#include "tcp.h"

#include <list>
#include <string>

using namespace std;

class Buffer;

class HttpConnection : public TcpConnection {
 public:
  HttpConnection();
  virtual ~HttpConnection();

  virtual bool addPacket(const Buffer& data);

 private:
  list<pair<string, string>> mRequestHeaders;
  Buffer* mRequestBody;
  list<pair<string, string>> mResponseHeaders;
  Buffer* mResponseBody;
};

#endif /* __HTTP_H__ */
