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

WebSocketFrame::WebSocketFrame(int flags, FrameType type) : mFlags(flags), mType(type), mData(nullptr), mDataLength(0), mSubject("No subject") {
}

WebSocketFrame::~WebSocketFrame() {
  if (mData) {
    free((void*) mData);
  }
}

int
WebSocketFrame::getFlags() const {
  return mFlags;
}

FrameType
WebSocketFrame::getType() const {
  return mType;
}

const char*
WebSocketFrame::getData() {
  return mData;
}

unsigned int
WebSocketFrame::getDataLength() {
  return mDataLength;
}

void
WebSocketFrame::setData(const char* data, unsigned int len) {
  mData = data;
  mDataLength = len;
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
  string dataStr(mData, mDataLength);
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

WebSocketParser::WebSocketParser() : mData(nullptr), mLength(0), mHeaderHandled(false), mLastFrameType(UNKNOWN) {
}

WebSocketParser::~WebSocketParser() {
  if (mData) {
    free((void*) mData);
  }
}

void
WebSocketParser::addStreamData(const char* data, unsigned int len) {
  if (strncmp(data, "GET /", 5) == 0
      || strncmp(data, "HTTP", 4) == 0) {
    mHeaderHandled = false;
  }

  mData = (char*) realloc(mData, mLength + len);
  memcpy(mData + mLength, data, len);
  mLength += len;
}

WebSocketFrame*
WebSocketParser::getNextFrame() {
  if (!mHeaderHandled) {
    char* pos = strstr(mData, "\r\n\r\n");

    if (pos) {
      char* data = (char*) malloc(mLength);
      memcpy(data, mData, pos - mData);

      WebSocketFrame* frame = new WebSocketFrame(0, UNKNOWN);
      frame->setSubject("HEADER");
      frame->setData(data, pos - mData);

      unsigned int len = pos - mData + 4;

      if (mLength > len) {
	mLength -= len;
	memmove(mData, pos, mLength);
      } else {
	mLength = 0;
      }

      mHeaderHandled = true;
      return frame;
    }
  }

  if (mLength >= 2) {
    uint8_t payloadHeaderLength = 2;
    uint16_t frameHeader = *((uint16_t*) mData);
    uint8_t frameFlags = (frameHeader & 0xf0) >> 4;
    FrameType frameType = static_cast<FrameType>(frameHeader & 0x0f);
    uint8_t frameMasked = (frameHeader & 0x8000) >> 15;
    uint64_t payloadLength = (frameHeader & 0x7f00) >> 8;

    if (payloadLength == 126) {
      payloadLength = ntohs(*((uint16_t*) (mData + 2)));
      payloadHeaderLength += 2;
    } else if (payloadLength == 127) {
      payloadLength = ntohl(*((uint32_t*) (mData + 2)));
      payloadLength += ((uint64_t) ntohl(*((uint32_t*) (mData + 6)))) << 32;
      payloadHeaderLength += 10;
    }

    if (frameMasked == 1) {
      payloadHeaderLength += 4;
    }

    if (mLength >= payloadHeaderLength + payloadLength) {
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

      char* payload = (char*) malloc(payloadLength + 1);
      payload[payloadLength] = '\0';
      memcpy(payload, mData + payloadHeaderLength, payloadLength);
      frame->setData(payload, payloadLength);
      mLength -= payloadHeaderLength + payloadLength;

      if (mLength > 0) {
	memmove(mData, mData + payloadHeaderLength + payloadLength, mLength);
      }

      return frame;
    }
  }

  return nullptr;
}
