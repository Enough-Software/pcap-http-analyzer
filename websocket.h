#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

class WebSocketFrame
{
 public:
  WebSocketFrame();
  virtual ~WebSocketFrame();

  const char* getData();
  void setData(const char* data);

  const char* getType();
  void setType(const char* data);

 private:
  const char* mData;
  const char* mType;
};

class WebSocketParser
{
 public:
  WebSocketParser();
  virtual ~WebSocketParser();

  void addStreamData(const char* data, uint16_t len);
  WebSocketFrame* getNextFrame();

 private:
  char* mData;
  uint16_t mLength;
  bool mHeaderHandled;
};

#endif // __WEBSOCKET_H__
