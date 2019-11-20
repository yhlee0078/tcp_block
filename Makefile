all : tcp_block

tcp_block: main.o
	g++ -g -w -o tcp_block main.o -lpcap

main.o:
	g++ -g -w -c -o main.o main.cpp

clean:
	rm -f send_arp
	rm -f *.o
