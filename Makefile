TARGET=	icom.o

.PHONY:	all
all:	$(TARGET)

icom.o:	icom.c
	clang -O2 -g -target bpf -c icom.c -I/usr/include/x86_64-linux-gnu/
