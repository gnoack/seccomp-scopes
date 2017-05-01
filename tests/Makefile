# TODO: Deduplicate flags between makefiles (makefile include?)
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g -O1

LIBS = ../pledge.so testlib.o
CFLAGS += -I..

bpfhelper: bpfhelper.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

inet: inet.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

paths: paths.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

stdio: stdio.o $(LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

TEST_BINARIES = paths stdio inet bpfhelper

badbpftest: ../pledge.o checkopt.sh
	./checkopt.sh ../pledge.o

test: $(TEST_BINARIES) badbpftest
	./inet
	./paths
	./stdio
	./bpfhelper

clean:
	rm -rf *.o *.so *~ $(TEST_BINARIES)

.PHONY: test clean
