CFLAGS= -fPIC -g -O1

c_exp1: c_exp1.o

test: c_exp1.o checkopt.sh
	./checkopt.sh c_exp1.o

clean:
	rm -f *.o *.so *~ c_exp1

.PHONY: test clean
