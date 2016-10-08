# TODO: Deduplicate flags between makefiles (makefile include?)
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g

LIBS = ../pledge.o testlib.o
CFLAGS += -I..

rpath: rpath.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

wpath: wpath.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

stdio: stdio.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

TEST_BINARIES = rpath wpath stdio

test: $(TEST_BINARIES)
	./stdio
	./rpath
	./wpath

clean:
	rm -rf *.o *.so *~ $(TEST_BINARIES)

.PHONY: test clean
