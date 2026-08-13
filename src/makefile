LDLIBS=-lpcap

all: send-arp-test

main.o: main.cpp arp_spoof.h common.h
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

arp_spoof.o: arp_spoof.cpp arp_spoof.h common.h
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

arphdr.o: arphdr.cpp arphdr.h mac.h ip.h
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

ethhdr.o: ethhdr.cpp ethhdr.h mac.h
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

ip.o: ip.cpp ip.h
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

mac.o: mac.cpp mac.h
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

send-arp-test: main.o arp_spoof.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o