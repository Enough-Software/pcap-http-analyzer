/*
  RFC 6455-compliant web socket parsing classes.

  See http://tools.ietf.org/html/rfc6455
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "websocket.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

WebSocketFrame::WebSocketFrame(int flags, FrameType type) : mFlags(flags), mType(type), mData(nullptr, 0), mSubject("No subject") {
}

WebSocketFrame::~WebSocketFrame() {
}

int
WebSocketFrame::getFlags() const {
  return mFlags;
}

FrameType
WebSocketFrame::getType() const {
  return mType;
}

const Buffer
WebSocketFrame::getData() const {
  return mData;
}

void
WebSocketFrame::setData(const Buffer& data) {
  mData = data;
}

string
WebSocketFrame::getSubject() const {
  return mSubject;
}

void
WebSocketFrame::setSubject(string subject) {
  mSubject = subject;
}

string
WebSocketFrame::typeAsString(FrameType type) {
  string str;

  switch (type) {
  case CONTINUATION:
    str = "CONTINUATION";
    break;

  case TEXT:
    str = "TEXT";
    break;

  case BINARY:
    str = "BINARY";
    break;

  case CONNECTION_CLOSE:
    str = "CONNECTION_CLOSE";
    break;

  case PING:
    str = "PING";
    break;

  case PONG:
    str = "PONG";
    break;

  default:
    str = "UNKNOWN";
    break;
  }

  return str;
}

NotificationFrame::NotificationFrame(int flags) : WebSocketFrame(flags, TEXT) {
}

NotificationFrame::~NotificationFrame() {
}

string
NotificationFrame::getSubject() const {
  string type("Unknown notification type");
  string dataStr(mData.getData(), mData.getLength());
  int posStart = dataStr.find("\"type\":\"");

  if (posStart >= 0) {
    posStart += 8;
    int posEnd = dataStr.find("\"", posStart + 1);

    if (posEnd >= 0) {
      type = dataStr.substr(posStart, posEnd - posStart);
    }
  }

  return type;
}

void
NotificationFrame::setSubject(string) {
  // Do nothing here. Subject is automatically set and we dont want to overwrite it.
}

WebSocketParser::WebSocketParser() : mBuffer(nullptr, 0), mHeaderHandled(false), mLastFrameType(UNKNOWN) {
}

WebSocketParser::~WebSocketParser() {
}

void
WebSocketParser::addStreamData(const Buffer& buffer) {
  if (buffer.startsWith("GET /") || buffer.startsWith("HTTP")) {
    mHeaderHandled = false;
  }

  mBuffer.append(buffer);
}

WebSocketFrame*
WebSocketParser::getNextFrame() {
  if (!mHeaderHandled) {
    int pos = mBuffer.indexOf("\r\n\r\n");

    if (pos > -1) {
      Buffer frameBuffer = mBuffer.subbuffer(0, pos);
      mBuffer = mBuffer.subbuffer(pos + 4);

      WebSocketFrame* frame = new WebSocketFrame(0, UNKNOWN);
      frame->setSubject("HEADER");
      frame->setData(frameBuffer);

      mHeaderHandled = true;
      return frame;
    }
  }

  if (mBuffer.getLength() >= 2) {
    const char* data = mBuffer.getData();
    uint8_t payloadHeaderLength = 2;
    uint16_t frameHeader = *((uint16_t*) data);
    uint8_t frameFlags = (frameHeader & 0xf0) >> 4;
    FrameType frameType = static_cast<FrameType>(frameHeader & 0x0f);
    uint8_t frameMasked = (frameHeader & 0x8000) >> 15;
    uint64_t payloadLength = (frameHeader & 0x7f00) >> 8;

    if (payloadLength == 126) {
      payloadLength = ntohs(*((uint16_t*) (data + 2)));
      payloadHeaderLength += 2;
    } else if (payloadLength == 127) {
      payloadLength = ntohl(*((uint32_t*) (data + 2)));
      payloadLength += ((uint64_t) ntohl(*((uint32_t*) (data + 6)))) << 32;
      payloadHeaderLength += 10;
    }

    if (frameMasked == 1) {
      payloadHeaderLength += 4;
    }

    if (mBuffer.getLength() >= payloadHeaderLength + payloadLength) {
      if (frameType != CONTINUATION) {
	mLastFrameType = frameType;
      }

      WebSocketFrame* frame;

      if (mLastFrameType == TEXT) {
	frame = new NotificationFrame(frameFlags);
      } else {
	frame = new WebSocketFrame(frameFlags, mLastFrameType);
	frame->setSubject(WebSocketFrame::typeAsString(frameType));
      }

      Buffer payloadBuffer = mBuffer.subbuffer(payloadHeaderLength, payloadLength);
      frame->setData(payloadBuffer);
      mBuffer = mBuffer.subbuffer(payloadHeaderLength + payloadLength);
      return frame;
    }
  }

  return nullptr;
}
