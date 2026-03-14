.PHONY: test test-macos test-linux test-linux-amd64 test-linux-arm64 build-linux clean

# Run all tests: macOS native + Linux containers
test: test-macos test-linux

# macOS: native cargo test (tests are isolated via tempdirs)
test-macos:
	cargo test --workspace

# Linux: both architectures
test-linux: test-linux-arm64 test-linux-amd64

# Linux arm64 (native on Apple Silicon, emulated on x86)
test-linux-arm64:
	docker build --platform linux/arm64 -t unsee-test:arm64 .
	docker run --rm --platform linux/arm64 unsee-test:arm64

# Linux amd64 (emulated on Apple Silicon, native on x86)
test-linux-amd64:
	docker build --platform linux/amd64 -t unsee-test:amd64 .
	docker run --rm --platform linux/amd64 unsee-test:amd64

# Build only (no tests)
build-linux:
	docker build --platform linux/arm64 -t unsee-test:arm64 .
	docker build --platform linux/amd64 -t unsee-test:amd64 .

clean:
	cargo clean
	docker rmi unsee-test:arm64 unsee-test:amd64 2>/dev/null || true
