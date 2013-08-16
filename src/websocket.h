#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

#include "buffer.h"

#include <string>

using namespace std;

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

  int getFlags() const;
  FrameType getType() const;

  const Buffer getData() const;
  void setData(const Buffer& data);

  virtual string getSubject() const;
  virtual void setSubject(string subject);

  static string typeAsString(FrameType type);

 protected:
  int mFlags;
  FrameType mType;
  Buffer mData;
  string mSubject;
};

class NotificationFrame : public WebSocketFrame
{
 public:
  NotificationFrame(int flags);
  virtual ~NotificationFrame();

  virtual string getSubject() const;
  virtual void setSubject(string subject);
};

class WebSocketParser
{
 public:
  WebSocketParser();
  virtual ~WebSocketParser();

  void addStreamData(const Buffer& buffer);
  WebSocketFrame* getNextFrame();

 private:
  Buffer mBuffer;
  bool mHeaderHandled;
  FrameType mLastFrameType;
};

#endif // __WEBSOCKET_H__
