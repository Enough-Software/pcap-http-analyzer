#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

enum FrameType {
  UNKNOWN = -1,
  // Non-control frames:
  CONTINUATION = 0,
  TEXT = 1,
  BINARY = 2,
  // Control frames:
  CONNECTION_CLOSE = 8,
  PING = 9,
  PONG = 10
};

class WebSocketFrame
{
 public:
  WebSocketFrame(int flags, FrameType type);
  virtual ~WebSocketFrame();

  int getFlags();
  FrameType getType();

  const char* getData();
  uint16_t getDataLength();
  void setData(const char* data, uint16_t len);

  virtual const char* getSubject();
  virtual void setSubject(const char* subject);

  static const char* typeAsString(FrameType type);

 protected:
  int mFlags;
  FrameType mType;
  const char* mData;
  uint16_t mDataLength;
  const char* mSubject;
};

class NotificationFrame : public WebSocketFrame
{
 public:
  NotificationFrame(int flags);
  virtual ~NotificationFrame();

  virtual const char* getSubject();
  virtual void setSubject(const char* subject);
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
  FrameType mLastFrameType;
};

#endif // __WEBSOCKET_H__
