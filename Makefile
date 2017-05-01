
LDFLAGS= -lc -lgcc -lbsd
CFLAGS= -fPIC -g -O1

PLEDGE_OBJECTS = pledge.o pledge_dns.o

pledge.so: $(PLEDGE_OBJECTS)
	$(LD) -shared -o $@ $^

pledge.o: pledge.c pledge.h bpf_helper.h

pledge_dns.o: pledge_dns.c bpf_helper.h

clean:
	rm -f *.o *.so *~

.PHONY: clean
