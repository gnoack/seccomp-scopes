######################################################################
# Compiler flags
######################################################################
LDFLAGS= -static -lc -lgcc
CFLAGS= -fPIC -g -O1 -I.

######################################################################
# Pledge main library
######################################################################
LIBRARY_OBJECTS = pledge.o pledge_dns.o pledge_inet.o pledge_path.o pledge_stdio.o

pledge.so: $(LIBRARY_OBJECTS)
	$(LD) -shared -o $@ $^

pledge.a: $(LIBRARY_OBJECTS)
	$(AR) -r $@ $^

######################################################################
# Tests
######################################################################
TEST_NAMES := inet paths stdio bpfhelper
TEST_BINARIES := $(TEST_NAMES:%=tests/%)
TEST_LIBS := tests/testlib.o pledge.a

tests/%: tests/%.o $(TEST_LIBS)
	$(CC) -o $@ $(LDFLAGS) $^

badbpftest: pledge.so tests/checkopt.sh
	tests/checkopt.sh pledge.so

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
	$(CC) -o $@ $(LDFLAGS) $^

######################################################################
# Clean up
######################################################################
clean:
	rm -f *.o *.so *.a *~ */*.o */*.so */*~ $(TEST_BINARIES) $(EXAMPLE_BINARIES)

.PHONY: clean test badbpftest
