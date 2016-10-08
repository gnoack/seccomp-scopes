# TODO: Deduplicate flags between makefiles (makefile include?)
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g

PLEDGE_LIB = ../pledge.o
CFLAGS += -I..

rpath: rpath.o $(PLEDGE_LIB)
	$(CC) -o $@ $(LDFLAGS) $^

wpath: wpath.o $(PLEDGE_LIB)
	$(CC) -o $@ $(LDFLAGS) $^

stdio: stdio.o $(PLEDGE_LIB)
	$(CC) -o $@ $(LDFLAGS) $^

TEST_BINARIES = rpath wpath stdio

test: $(TEST_BINARIES)
	./rpath
	./wpath
	./stdio

clean:
	rm -rf *.o *.so *~ $(TEST_BINARIES)

.PHONY: test clean
