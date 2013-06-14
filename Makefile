CXXFLAGS=-g -O0 -Wall -Wextra -Werror -pedantic

default: pcap_dump

clean:
	rm -f pcap_dump *.o

main.o: main.cc
	g++ $(CXXFLAGS) -c main.cc

websocket.o: websocket.cc
	g++ $(CXXFLAGS) -c websocket.cc

pcap_dump: main.o websocket.o
	g++ -o pcap_dump main.o websocket.o -lpcap

run: pcap_dump
	./pcap_dump /home/mkoch/acceptence-bug-A-party.pcapng
