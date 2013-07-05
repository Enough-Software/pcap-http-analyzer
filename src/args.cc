#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "args.h"

#include <getopt.h>
#include <sstream>

void
Args::parseWebSocketPorts(string webSocketList) {
  mWebSocketPorts.clear();

  string item;
  stringstream ss(webSocketList);

  while (getline(ss, item, ',')) {
    unsigned short port = strtoul(item.c_str(), NULL, 0);
    mWebSocketPorts.insert(port);
  }
}

void
Args::printUsage(string programName) {
  fprintf(stderr, "\nUsage: %s [OPTIONS] filename\n\n", programName.c_str());
  fprintf(stderr, "  --short, -s     short output format, no detailed messages\n");
  fprintf(stderr, "  --stopwatch, -0 short output format, no detailed messages\n");
  fprintf(stderr, "  --ws-ports=...  comma separated list of ports used for RFC 6455 compliant web socket connections\n\n");
  exit(1);
}

Args::Args() {
}

Args::Args(int argc, char** argv) : mUseShortOutputFormat(false), mUseStopwatchFormat(false) {
  mWebSocketPorts.insert(8089);

  static struct option long_options[] = {
    { "filter",    required_argument, 0, 'f'},
    { "short",     no_argument,       0, 's'},
    { "stopwatch", no_argument,       0, '0'},
    { "ws-ports",  required_argument, 0, 'w'},
    { 0, 0, 0, 0 }
  };

  while (1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "f:sw:0", long_options, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
    case 's':
      mUseShortOutputFormat = true;
      break;

    case 'w':
      parseWebSocketPorts(optarg);
      break;

    case '0':
      mUseStopwatchFormat = true;
      break;

    default:
      printUsage(argv[0]);
      break;
    }
  }

  if (optind < argc) {
    while (optind < argc) {
      mFiles.push_back(argv[optind++]);
    }
  } else {
    mFiles.push_back("-");
  }
}

Args::~Args() {
}

bool
Args::useShortOutputFormat() {
  return mUseShortOutputFormat;
}

bool
Args::useStopwatchFormat() {
  return mUseStopwatchFormat;
}

set<unsigned short>&
Args::getWebSocketPorts() {
  return mWebSocketPorts;
}

list<string>&
Args::getFiles() {
  return mFiles;
}
