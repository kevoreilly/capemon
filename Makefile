MAKEFLAGS = -j8
CFLAGS = -Wall -std=c99 -s -O2 -Wno-strict-aliasing -static
DLL = -shared
DIRS = -Idistorm/include -Ibson
LIBS = -lws2_32 -lshlwapi
OBJDIR = objects

# Passes DBG=1 on as -DCUCKOODBG=1
ifdef DBG
	CFLAGS += -DCUCKOODBG=$(DBG)
endif

ifneq ($(OS),Windows_NT)
	CC = i686-w64-mingw32-gcc
else
	CC = gcc
endif

DISTORM3 = $(wildcard distorm/src/*.c)
DISTORM3OBJ = $(DISTORM3:distorm/src/%.c=$(OBJDIR)/distorm3.2/%.o)

CUCKOOSRC = $(wildcard *.c)
CUCKOOOBJ = $(CUCKOOSRC:%.c=$(OBJDIR)/%.o)

BSONSRC = bson/bson.c bson/encoding.c bson/numbers.c
BSONOBJ = $(OBJDIR)/bson/bson.o $(OBJDIR)/bson/encoding.o $(OBJDIR)/bson/numbers.o

default: $(OBJDIR) cuckoomon.dll

$(OBJDIR):
	mkdir $@ $@/bson $@/distorm3.2

$(OBJDIR)/distorm3.2/%.o: distorm/src/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/bson/%.o: bson/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOOOBJ) $(DISTORM3OBJ) $(BSONOBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(OBJDIR) cuckoomon.dll
