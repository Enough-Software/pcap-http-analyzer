CXXFLAGS=-g -O0 -Wall -Wextra -Werror -pedantic
INCLUDES=
LDFLAGS=-lpcap
PCAPFILE=tests/test.pcapng

SOURCES:=$(wildcard *.cc)
OBJECTS=$(SOURCES:.cc=.o)

default: pcap_dump

clean:
	rm -f pcap_dump pcap_dump_static *.o

.cc.o:
	g++ $(CXXFLAGS) $(INCLUDES) -c $<

pcap_dump: $(OBJECTS)
	g++ -o pcap_dump $(OBJECTS) $(LDFLAGS)

pcap_dump_static: pcap_dump
	g++ -static -o pcap_dump_static main.o websocket.o $(LDFLAGS)

run: pcap_dump
	./pcap_dump $(PCAPFILE)

debug: pcap_dump
	gdb --args pcap_dump $(PCAPFILE)

valgrind: pcap_dump
	valgrind ./pcap_dump $(PCAPFILE)
