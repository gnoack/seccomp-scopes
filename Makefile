######################################################################
# Compiler flags
######################################################################
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g -O1 -I.

######################################################################
# Pledge main library
######################################################################
LIBRARY_OBJECTS = pledge.o pledge_dns.o pledge_inet.o pledge_path.o pledge_stdio.o

pledge.so: $(LIBRARY_OBJECTS)
	$(LD) -shared -o $@ $^

pledge.o: pledge.c pledge.h bpf_helper.h

######################################################################
# Tests
######################################################################
TEST_NAMES := inet paths stdio bpfhelper
TEST_BINARIES := $(TEST_NAMES:%=tests/%)
TEST_LIBS := pledge.so tests/testlib.o

tests/%: tests/%.o $(TEST_LIBS)
	$(CC) -o $@ $(LDFLAGS) -Wl,-rpath=. $^

badpbftest: pledge.o tests/checkopt.sh
	tests/checkopt.sh pledge.o

test: $(TEST_BINARIES) badbpftest
	@for binary in $(TEST_BINARIES); do \
	  $$binary; \
	done

######################################################################
# Examples
######################################################################
EXAMPLE_NAMES := cat
EXAMPLE_BINARIES := $(EXAMPLE_NAMES:%=examples/%)
EXAMPLE_LIBS := pledge.so

example: $(EXAMPLE_BINARIES)

examples/%: examples/%.o $(EXAMPLE_LIBS)
	$(CC) -o $@ $(LDFLAGS) -Wl,-rpath=. $^

######################################################################
# Clean up
######################################################################
clean:
	rm -f *.o *.so *~ */*.o */*.so */*~ $(TEST_BINARIES) $(EXAMPLE_BINARIES)

.PHONY: clean test badbpftest
