#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "websocket.h"

WebSocketFrame::WebSocketFrame() : mData(NULL) {
}

WebSocketFrame::~WebSocketFrame() {
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
WebSocketFrame::getType() {
  return mType;
}

void
WebSocketFrame::setType(const char* type) {
  mType = type;
}

WebSocketParser::WebSocketParser() : mData(NULL), mLength(0), mHeaderHandled(false) {
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

      WebSocketFrame* frame = new WebSocketFrame();
      frame->setType("HEADER");
      frame->setData("HEADER DATA");
      return frame;
    }
  }

  if (mLength >= 4) {
    uint16_t payloadLength = ntohs(*((uint16_t*) (mData + 2)));

    if (mLength >= payloadLength + 4) {
      char* payload = (char*) malloc(payloadLength + 1);
      payload[payloadLength] = '\0';
      memcpy(payload, mData + 4, payloadLength);
      mLength -= payloadLength + 4;

      if (mLength > 0) {
	memmove(mData, mData + 4 + payloadLength, mLength);
      }

      const char* typePosition = strstr(payload, "\"type\":\"");
      char* type = "Unknown notification type";

      if (typePosition) {
	const char* typeStart = typePosition + 8;
	const char* typeEnd = strchr(typeStart, '\"');

	if (typeEnd) {
	  int len = typeEnd - typeStart;
	  type = (char*) malloc(len + 1);
	  type[len] = '\0';
	  memcpy(type, typeStart, len);
	}
      }

      WebSocketFrame* frame = new WebSocketFrame();
      frame->setType(type);
      frame->setData(payload);
      return frame;
    }
  }

  return NULL;
}
