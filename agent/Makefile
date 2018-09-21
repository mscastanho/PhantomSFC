# Based on code from BPFabric project - https://github.com/UofG-netlab/BPFabric.git
CFLAGS := -I../ubpf/inc -I../protocol/src/c -I../bpfmap

all: agent.o

agent.o: agent.c
	$(CC) $(CFLAGS) -c $<
	$(AR) cr agent.a agent.o

clean:
	$(RM) -f *.o *.a
