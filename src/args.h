#ifndef __ARGS_H__
#define __ARGS_H__

#include <list>
#include <set>
#include <string>

using namespace std;

class Args {
 public:
  Args();
  Args(int argc, char** argv);
  virtual ~Args();

  bool useShortOutputFormat();
  bool useStopwatchFormat();
  set<unsigned short>& getWebSocketPorts();
  list<string>& getFiles();

 private:
  void parseWebSocketPorts(string ports);
  void printUsage(string programName);

 private:
  bool mUseShortOutputFormat;
  bool mUseStopwatchFormat;
  set<unsigned short> mWebSocketPorts;
  list<string> mFiles;
};

#endif /* __ARGS_H__ */
