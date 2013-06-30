bin_PROGRAMS = pcap-http-analyzer

pcap_http_analyzer_SOURCES = main.cc websocket.cc commparty.cc print.cc
pcap_http_analyzer_CPPFLAGS = $(JSON_CFLAGS) -DENABLE_JSON
pcap_http_analyzer_LDADD = $(JSON_LIBS) -lpcap
