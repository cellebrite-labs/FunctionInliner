# building for arm64-apple-macosx11 (or iOS) naively using clang will imply -target-abi=darwinpcs
# which apparently disables -moutline, so we have to compile "manually"

CC=clang -cc1
LD=clang

TARGET=arm64-apple-macosx11

CFLAGS=-triple $(TARGET) -emit-obj -fgnuc-version=4.2.1 \
	-isystem /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include \

O3_CFLAGS=-O3
O3_MOUTLINE_CFLAGS=-O3 -mllvm -enable-machine-outliner

LDFLAGS=-target $(TARGET)

all: gzip-O3 gzip-O3-moutline

%-O3.o: %.c
	$(CC) $(CFLAGS) $(O3_CFLAGS) -o $@ $<

%-O3-moutline.o: %.c
	$(CC) $(CFLAGS) $(O3_MOUTLINE_CFLAGS) -o $@ $<

gzip-O3: gzip-O3.o
	$(LD) $(LDFLAGS) -o $@ $^

gzip-O3-moutline: gzip-O3-moutline.o
	$(LD) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o gzip-O3 gzip-O3-moutline
