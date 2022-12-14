LDLIBS=-lpcap

all: beacon-flood

mac.o : mac.h mac.cpp

main.o : mac.h main.cpp

beacon-flood: mac.o main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f beacon-flood *.o