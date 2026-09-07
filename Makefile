CC=cc
BREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
LIBUSB_PREFIX := $(shell brew --prefix libusb 2>/dev/null || echo $(BREW_PREFIX)/opt/libusb)
CFLAGS=-O2 -g -std=c11 -Wall -Wextra -Iinclude -I$(LIBUSB_PREFIX)/include/libusb-1.0
LDFLAGS=-L$(LIBUSB_PREFIX)/lib -lusb-1.0 -pthread -framework SystemConfiguration -framework CoreFoundation
SRC=src/main.c src/rndis.c src/usb.c src/utun.c src/frame.c src/dhcp.c src/net_util.c src/route.c src/status.c
BIN=build/android-rndis-macos
TEST_BIN=build/test-cabled
APP=build/AndroidRNDIS.app

all: $(BIN)

$(BIN): $(SRC) include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

app: $(BIN)
	@mkdir -p $(APP)/Contents/MacOS
	swiftc -O ui/MenuApp.swift -o $(APP)/Contents/MacOS/AndroidRNDIS
	cp resources/AndroidRNDIS-Info.plist $(APP)/Contents/Info.plist
	codesign --force --deep -s - $(APP)

install: app
	launchctl bootout system/com.android-rndis-macos.daemon 2>/dev/null || true
	mkdir -p /usr/local/bin
	install -m 755 build/android-rndis-macos /usr/local/bin/android-rndis-macos
	install -m 644 -o root -g wheel resources/com.android-rndis-macos.plist /Library/LaunchDaemons/com.android-rndis-macos.plist
	if [ -n "$$SUDO_USER" ]; then chown -R "$$SUDO_USER" build; fi
	@echo "installed (daemon starts on first toggle-on, not at boot)."
	@echo "menu app: open build/AndroidRNDIS.app (drag to /Applications)"

uninstall:
	launchctl bootout system/com.android-rndis-macos.daemon 2>/dev/null || true
	rm -f /usr/local/bin/android-rndis-macos /Library/LaunchDaemons/com.android-rndis-macos.plist
	@echo "uninstalled (menu app is a plain .app, drag to Trash)"

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

.PHONY: all clean test san fuzz app install uninstall

build/test-usb: tests/test_usb.c src/usb.c src/rndis.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/test_usb.c src/rndis.c -o $@ $(LDFLAGS)

test-usb: build/test-usb
	./build/test-usb

build/probe-dhcp: tests/probe_dhcp.c src/usb.c src/dhcp.c src/frame.c src/rndis.c src/net_util.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) tests/probe_dhcp.c src/usb.c src/dhcp.c src/frame.c src/rndis.c src/net_util.c -o $@ $(LDFLAGS)

probe-dhcp: build/probe-dhcp
	./build/probe-dhcp

.PHONY: test-usb probe-dhcp

build/test-signal: tests/test_signal.c $(SRC) include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/test_signal.c $(filter-out src/main.c,$(SRC)) -o $@ $(LDFLAGS)

test-signal: build/test-signal
	./build/test-signal

check: test san fuzz test-usb test-signal test-dhcp test-utun

.PHONY: test-signal check

build/test-dhcp: tests/test_dhcp.c src/dhcp.c src/net_util.c src/rndis.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/test_dhcp.c src/dhcp.c src/net_util.c src/rndis.c -o $@

test-dhcp: build/test-dhcp
	./build/test-dhcp

.PHONY: test-dhcp

build/test-utun: tests/test_utun.c src/utun.c include/*.h
	@mkdir -p build
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/test_utun.c src/utun.c -o $@

test-utun: build/test-utun
	./build/test-utun

.PHONY: test-utun
