#ifndef __BUFFFER_H__
#define __BUFFFER_H__

#include <string>

using namespace std;

class Buffer {
 public:
  Buffer();
  Buffer(const char* data, unsigned int length);
  Buffer(const Buffer& other);
  virtual ~Buffer();

  Buffer& operator=(const Buffer& rhs);
  const char operator[](unsigned int index) const;

  static Buffer copy(const char* data, unsigned int length);

  const char* getData() const;
  unsigned int getLength() const;

  void append(const Buffer& other);
  Buffer subbuffer(unsigned int start) const;
  Buffer subbuffer(unsigned int start, unsigned int length) const;
  bool startsWith(const string str) const;
  int indexOf(const string str) const;

 private:
  char* mData;
  unsigned int mLength;
};

#endif /* __BUFFFER_H__ */
