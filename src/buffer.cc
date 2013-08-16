#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "buffer.h"

#include <stdlib.h>
#include <string.h>

Buffer::Buffer(const char* data, unsigned int length) {
  mData = (char*) malloc(length);
  mLength = length;
  memcpy(mData, data, length);
}

Buffer::Buffer(const Buffer& other) : Buffer(other.mData, other.mLength) {
}

Buffer::~Buffer() {
  if (mData) {
    free(mData);
  }
}

Buffer&
Buffer:: operator=(const Buffer& rhs) {
  if (mData) {
    free(mData);
  }

  mLength = rhs.mLength;
  mData = (char*) malloc(mLength);
  memcpy(mData, rhs.mData, mLength);
  return *this;
}

Buffer
Buffer::copy(const char* data, unsigned int length) {
  char* copyData = (char*) malloc(length);
  memcpy(copyData, data, length);
  return Buffer(copyData, length);
}

const char
Buffer::operator[](unsigned int index) const {
  return mData[index];
}

const char*
Buffer::getData() const {
  return (const char*) mData;
}

unsigned int
Buffer::getLength() const {
  return mLength;
}

void
Buffer::append(const Buffer& other) {
  if (mData && mLength > 0) {
    if (other.mData && other.mLength > 0) {
      char* data = (char*) malloc(mLength + other.mLength);
      memcpy(data, mData, mLength);
      memcpy(data + mLength, other.mData, other.mLength);
      free(mData);
      mData = data;
      mLength += other.mLength;
    }
  } else if (other.mData && other.mLength > 0) {
    char* data = (char*) malloc(other.mLength);
    memcpy(data, other.mData, other.mLength);

    if (mData) {
      free(mData);
    }

    mData = data;
    mLength += other.mLength;
  }
}

Buffer
Buffer::subbuffer(unsigned int start) const {
  return subbuffer(start, mLength - start);
}

Buffer
Buffer::subbuffer(unsigned int start, unsigned int length) const {
  return Buffer(mData + start, length);
}

bool
Buffer::startsWith(const string str) const {
  string dataStr(mData, mLength);
  return dataStr.find(str) == 0;
}

int
Buffer::indexOf(const string str) const {
  char* pos = (char*) memmem(mData, mLength, str.c_str(), str.length());
  return pos - mData;
}
