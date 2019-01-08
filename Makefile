CC=gcc
W32CC=i686-w64-mingw32-g++
W64CC=x86_64-w64-mingw32-g++
CFLAGS=-std=c++11 -I. -Wall -Werror -masm=intel
LDFLAGS=-static-libstdc++ -static-libgcc -lpthread -static -pipe

all: _samples debug shellcodes

_samples:
	$(W32CC) samples/hello.cpp -o build/hello32.dll $(CFLAGS) $(LDFLAGS) -shared
	$(W64CC) samples/hello.cpp -o build/hello64.dll $(CFLAGS) $(LDFLAGS) -shared

debug:
	$(W32CC) src/LoadLibrary.cpp -o build/debug32.exe $(CFLAGS) $(LDFLAGS) -DDEBUG
	$(W64CC) src/LoadLibrary.cpp -o build/debug64.exe $(CFLAGS) $(LDFLAGS) -DDEBUG

shellcodes:
	$(W64CC) src/LoadLibrary.cpp -c -o build/LoadLibrary.o $(CFLAGS) -fno-asynchronous-unwind-tables
	./deps/objconv/objconv -fnasm build/LoadLibrary.o
	@sed -i '1,/^.text/d' build/LoadLibrary.asm
	@sed -ni '1,/^SECTION .data/p' build/LoadLibrary.asm
	@sed -i 's/^SECTION .data.*//' build/LoadLibrary.asm
	@sed -i '1 i\jmp payload' build/LoadLibrary.asm
	@sed -i '1 i\[bits 64]' build/LoadLibrary.asm
	@sed -i 's/call    memcpy  /call    mymemcpy/g' build/LoadLibrary.asm
	nasm -fbin -o build/LoadLibrary.bin build/LoadLibrary.asm
	xxd -i build/LoadLibrary.bin > build/LoadLibrary.h
	sed -i 's/build_LoadLibrary_bin/LoadLibrary/g' build/LoadLibrary.h

clean:
	rm -rf build/*
