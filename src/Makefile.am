bin_PROGRAMS = pcap-http-analyzer

pcap_http_analyzer_SOURCES = \
    main.cc \
    buffer.cc \
    buffer.h \
    commparty.cc \
    commparty.h \
    http.cc \
    http.h \
    print.cc \
    print.h\
    tcp.cc \
    tcp.h \
    websocket.cc \
    websocket.h
pcap_http_analyzer_CPPFLAGS = $(JSON_CFLAGS)
pcap_http_analyzer_CXXFLAGS = -std=c++11
pcap_http_analyzer_LDADD = $(JSON_LIBS) -lpcap
