CC=gcc

CFLAGS+=-c -Wall -O3 -fno-strict-aliasing -DOSX
LDFLAGS+= #-lpcap  

SOURCES=mac-darktest.c  create-interface.c util.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=mac-darktest

all: clean $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS)   $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o mac-darktest
