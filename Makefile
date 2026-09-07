CC=cc
BREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
LIBUSB_PREFIX := $(shell brew --prefix libusb 2>/dev/null || echo $(BREW_PREFIX)/opt/libusb)
CFLAGS=-std=c11 -Wall -Wextra -Iinclude -I$(LIBUSB_PREFIX)/include/libusb-1.0
LDFLAGS=-L$(LIBUSB_PREFIX)/lib -lusb-1.0 -pthread
SRC=src/main.c src/rndis.c src/usb.c src/utun.c src/frame.c src/dhcp.c src/net_util.c src/route.c
BIN=build/cabled-hotspot
TEST_BIN=build/test-cabled

all: $(BIN)

$(BIN): $(SRC) include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

san: tests/test_all.c src/rndis.c src/frame.c src/dhcp.c src/net_util.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/test_all.c src/rndis.c src/frame.c src/dhcp.c src/net_util.c -o build/test-cabled-san
	./build/test-cabled-san

fuzz: build/test-fuzz
	./build/test-fuzz

build/test-fuzz: tests/test_fuzz.c src/rndis.c src/frame.c src/dhcp.c src/net_util.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/test_fuzz.c src/rndis.c src/frame.c src/dhcp.c src/net_util.c -o build/test-fuzz

$(TEST_BIN): tests/test_all.c src/rndis.c src/frame.c src/dhcp.c src/net_util.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) tests/test_all.c src/rndis.c src/frame.c src/dhcp.c src/net_util.c -o $(TEST_BIN)

clean:
	rm -rf build src/*.o

.PHONY: all clean test san fuzz
