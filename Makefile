
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g -O1

PLEDGE_OBJECTS = pledge.o

pledge.so: $(PLEDGE_OBJECTS)
	$(LD) -shared -o $@ $^

clean:
	rm -f *.o *.so *~

.PHONY: clean
