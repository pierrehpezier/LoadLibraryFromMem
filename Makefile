CC=gcc
W32CC=i686-w64-mingw32-g++
W64CC=x86_64-w64-mingw32-g++
CFLAGS=-std=c++11 -I.
LDFLAGS=-static-libstdc++ -static-libgcc -lpthread -static -pipe

all: _samples main

_samples:
	$(W32CC) samples/hello.cpp -o build/hello32.dll $(CFLAGS) $(LDFLAGS) -shared
	$(W64CC) samples/hello.cpp -o build/hello64.dll $(CFLAGS) $(LDFLAGS) -shared

main:
	$(W32CC) src/LoadLibrary.cpp -o build/debug32.exe $(CFLAGS) $(LDFLAGS) -DDEBUG

clean:
	rm -rf build/*
