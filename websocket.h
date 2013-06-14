#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

class WebSocketFrame
{
 public:
  WebSocketFrame();
  virtual ~WebSocketFrame();

  const char* getData();
  void setData(const char* data);
};

class WebSocketParser
{
 public:
  WebSocketParser();
  virtual ~WebSocketParser();

  void addStreamData(const char* data, unsigned int len);
  WebSocketFrame* getNextFrame();
};

#endif // __WEBSOCKET_H__
