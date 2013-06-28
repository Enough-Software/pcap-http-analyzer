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
  void setData(const char* data);

  const char* getSummary();
  void setSummary(const char* summary);

  static const char* typeAsString(FrameType type);

 private:
  int mFlags;
  FrameType mType;
  const char* mData;
  const char* mSummary;
};

// TODO: Create class NotificationFrame
//class NotificationFrame : WebSocketFrame

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
