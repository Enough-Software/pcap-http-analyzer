CXXFLAGS=-g -O0 -Wall -Wextra -Werror -pedantic
INCLUDES=
LDFLAGS=-lpcap
PCAPFILE=test.pcapng
PCAPFILE=test2.pcapng
PCAPFILE=multi-test.pcapng

default: pcap_dump

clean:
	rm -f pcap_dump pcap_dump_static *.o

main.o: main.cc
	g++ $(CXXFLAGS) $(INCLUDES) -c main.cc

websocket.o: websocket.cc
	g++ $(CXXFLAGS) $(INCLUDES) -c websocket.cc

pcap_dump: main.o websocket.o
	g++ -o pcap_dump main.o websocket.o $(LDFLAGS)

pcap_dump_static: pcap_dump
	g++ -static -o pcap_dump_static main.o websocket.o $(LDFLAGS)

run: pcap_dump
	./pcap_dump $(PCAPFILE)

debug: pcap_dump
	gdb --args pcap_dump $(PCAPFILE)

valgrind: pcap_dump
	valgrind ./pcap_dump $(PCAPFILE)