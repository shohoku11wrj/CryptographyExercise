# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror
LDFLAGS = -Wl,-rpath,/usr/lib

# Libraries against which the object file for each utility should be linked
INCLUDES = /usr/include/
LIBS = /usr/lib/ 
DCRYPTINCLUDE = /usr/local/include/ #/home/nicolosi/devel/libdcrypt/include/
DCRYPTLIB = /usr/local/lib/ #/home/nicolosi/devel/libdcrypt/lib/
DMALLOC = #-ldmalloc
GMP = -lgmp
DCRYPT = -ldcrypt

# The source file(s) for each program
all : skgu_pki skgu_nidh

pv_misc.o : pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c pv_misc.c

skgu_misc.o : skgu_misc.c skgu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c skgu_misc.c

skgu_cert.o : skgu_cert.c skgu.h pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c skgu_cert.c

skgu_pki.o : skgu_pki.c skgu.h pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c skgu_pki.c

skgu_pki : skgu_pki.o skgu_cert.o skgu_misc.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o skgu_cert.o skgu_misc.o pv_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

skgu_nidh.o : skgu_nidh.c skgu.h pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c skgu_nidh.c

skgu_nidh : skgu_nidh.o skgu_cert.o skgu_misc.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o skgu_cert.o skgu_misc.o pv_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

clean:
	-rm -f core *.core *.o *~ 

.PHONY: all clean
