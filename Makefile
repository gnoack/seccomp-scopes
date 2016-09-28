
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC

PLEDGE_OBJECTS = pledge.o

pledge.so: $(PLEDGE_OBJECTS)
	$(LD) -shared -o $@ $^

clean:
	rm -f *.o *.so *~ main

.PHONY: clean

main: main.o pledge.o
	$(CC) -o $@ $(LDFLAGS) $^
