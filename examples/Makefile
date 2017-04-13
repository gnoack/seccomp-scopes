# TODO: Deduplicate flags between makefiles (makefile include?)
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g -O1

LIBS = ../pledge.o
CFLAGS += -I..

cat: cat.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

BINARIES = cat

clean:
	rm -rf *.o $(BINARIES)

.PHONY: clean
