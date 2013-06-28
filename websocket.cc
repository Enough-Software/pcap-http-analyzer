#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "websocket.h"

WebSocketFrame::WebSocketFrame(int flags, FrameType type) : mFlags(flags), mType(type), mData(NULL), mSummary(NULL) {
}

WebSocketFrame::~WebSocketFrame() {
}

FrameType
WebSocketFrame::getType() {
  return mType;
}

const char*
WebSocketFrame::getData() {
  return mData;
}

void
WebSocketFrame::setData(const char* data) {
  mData = data;
}

const char*
WebSocketFrame::getSummary() {
  return mSummary;
}

void
WebSocketFrame::setSummary(const char* summary) {
  mSummary = summary;
}

const char*
WebSocketFrame::typeAsString(FrameType type) {
  const char* str;

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

WebSocketParser::WebSocketParser() : mData(NULL), mLength(0), mHeaderHandled(false), mLastFrameType(CONTINUATION) {
}

WebSocketParser::~WebSocketParser() {
  if (mData) {
    delete mData;
  }
}

void
WebSocketParser::addStreamData(const char* data, uint16_t len) {
  mData = (char*) realloc(mData, mLength + len);
  memcpy(mData + mLength, data, len);
  mLength += len;
}

WebSocketFrame*
WebSocketParser::getNextFrame() {
  if (mHeaderHandled == false) {
    char* pos = strstr(mData, "\r\n\r\n");

    if (pos) {
      unsigned int len = pos - mData + 4;

      if (mLength > len) {
	mLength -= len;
	memmove(mData, pos, mLength);
      } else {
	mLength = 0;
      }

      mHeaderHandled = true;

      WebSocketFrame* frame = new WebSocketFrame(0, UNKNOWN);
      frame->setData("HEADER DATA");
      frame->setSummary("HEADER");
      return frame;
    }
  }

  if (mLength >= 2) {
    uint8_t payloadHeaderLength = 2;
    uint16_t frameHeader = *((uint16_t*) mData);
    uint8_t frameFlags = (frameHeader & 0xf0) >> 4;
    FrameType frameType = static_cast<FrameType>(frameHeader & 0x0f);
    uint64_t payloadLength = (frameHeader & 0xff00) >> 8;

    if (payloadLength == 126) {
      payloadLength = ntohs(*((uint16_t*) (mData + 2)));
      payloadHeaderLength += 2;
    } else if (payloadLength == 127) {
      payloadLength = ntohl(*((uint32_t*) (mData + 2)));
      payloadLength += ((uint64_t) ntohl(*((uint32_t*) (mData + 6)))) << 32;
      payloadHeaderLength += 10;
    }

    if (mLength >= payloadHeaderLength + payloadLength) {
      if (frameType != CONTINUATION) {
	mLastFrameType = (FrameType) frameType; 
      }

      char* payload = (char*) malloc(payloadLength + 1);
      payload[payloadLength] = '\0';
      memcpy(payload, mData + payloadHeaderLength, payloadLength);
      mLength -= payloadHeaderLength + payloadLength;

      if (mLength > 0) {
	memmove(mData, mData + payloadHeaderLength + payloadLength, mLength);
      }

      char* summary = "Unknown notification type";

      if (mLastFrameType == TEXT) {
	const char* typeStart = strstr(payload, "\"type\":\"");
	const char* typeEnd = NULL;

	if (typeStart) {
	  typeStart = typeStart + 8;
	  typeEnd = strchr(typeStart, '\"');

	  if (typeEnd) {
	    int len = typeEnd - typeStart;
	    summary = (char*) malloc(len + 1);
	    summary[len] = '\0';
	    memcpy(summary, typeStart, len);
	  }
	}
      } else {
	summary = (char*) WebSocketFrame::typeAsString(frameType);
      }

      WebSocketFrame* frame = new WebSocketFrame(frameFlags, mLastFrameType);
      frame->setData(payload);
      frame->setSummary(summary);
      return frame;
    }
  }

  return NULL;
}
