#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "args.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <sstream>

void
Args::parseFilter(string filter) {
  mFilters.clear();
  string item;
  stringstream ss(filter);

  while (getline(ss, item, ',')) {
    unsigned short netbits = 32;
    string::size_type pos = item.find('/');

    if (pos != string::npos) {
      string netbitsStr = item.substr(pos + 1);
      item = item.substr(0, pos);
      netbits = atoi(netbitsStr.c_str());
    }

    struct in_addr addr;

    if (inet_aton(item.c_str(), &addr)) {
      mFilters.push_back(Netmask(IPv4(addr), netbits));
    }
  }
}

void
Args::parseHttpPorts(string ports) {
  mHttpPorts.clear();

  string item;
  stringstream ss(ports);

  while (getline(ss, item, ',')) {
    unsigned short port = strtoul(item.c_str(), NULL, 0);
    mHttpPorts.insert(port);
  }
}

void
Args::parseWebSocketPorts(string ports) {
  mWebSocketPorts.clear();

  string item;
  stringstream ss(ports);

  while (getline(ss, item, ',')) {
    unsigned short port = strtoul(item.c_str(), NULL, 0);
    mWebSocketPorts.insert(port);
  }
}

void
Args::printUsage(string programName) {
  fprintf(stderr, "\nUsage: %s [OPTIONS] filename\n\n", programName.c_str());
  fprintf(stderr, "  --filter, -f      filter for internal devices, comma separated list of netmasks\n");
  fprintf(stderr, "                    e.g.: -f 192.168.2.107/32,192.168.2.109/32\n");
  fprintf(stderr, "  --short, -s       short output format, no detailed messages\n");
  fprintf(stderr, "  --stopwatch, -0   don't use wall clock time for packets, instead start at 00:00:00\n");
  fprintf(stderr, "  --http-ports=...  comma separated list of ports used for HTTP/REST connections\n");
  fprintf(stderr, "  --ws-ports=...    comma separated list of ports used for RFC 6455 compliant web socket connections\n\n");
  exit(1);
}

Args::Args() {
}

Args::Args(int argc, char** argv) : mUseShortOutputFormat(false), mUseStopwatchFormat(false) {
  static struct option long_options[] = {
    { "filter",     required_argument, 0, 'f'},
    { "short",      no_argument,       0, 's'},
    { "stopwatch",  no_argument,       0, '0'},
    { "http-ports", required_argument, 0, 'h'},
    { "ws-ports",   required_argument, 0, 'w'},
    { 0, 0, 0, 0 }
  };

  while (1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "f:sh:w:0", long_options, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
    case 'f':
      parseFilter(optarg);
      break;

    case 's':
      mUseShortOutputFormat = true;
      break;

    case 'h':
      parseHttpPorts(optarg);
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

list<Netmask>
Args::getFilters() {
  return mFilters;
}

set<unsigned short>&
Args::getHttpPorts() {
  return mHttpPorts;
}

set<unsigned short>&
Args::getWebSocketPorts() {
  return mWebSocketPorts;
}

list<string>&
Args::getFiles() {
  return mFiles;
}
