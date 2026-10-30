# Builds the tcc-wasm kit with TinyCC. See README.md.
TCC ?= tcc
CC ?= cc
CFLAGS = -std=c99 -Wall -Werror -Isrc
CLANG_FLAGS = -std=c99 -Wall -Wextra -Wswitch-enum -Werror -fsyntax-only -Isrc
FRONT = src/front/base.c src/front/lexer.c src/front/parser.c src/front/fmt.c src/front/front.c src/front/eval.c src/front/check.c src/front/lower.c src/front/poseidon2.c src/front/sha512.c src/front/ed25519.c
TARGET = src/wasm.c
SRC = src/main.c $(FRONT) $(TARGET)
FRONT_TOOL = test/fronttool.c $(filter-out src/front/front.c src/front/lower.c,$(FRONT))
CHECK_TOOL = test/checktool.c $(FRONT) $(TARGET) build/domain.c
HEADERS = $(wildcard src/*.h src/front/*.h)

.PHONY: build check check-clang clean

build: build/langc build/fronttool

build/domain.c: domain/domain.lang gen/embed.c
	mkdir -p build
	$(TCC) -run gen/embed.c domain/domain.lang build/domain.c

build/langc: $(SRC) $(HEADERS) build/domain.c
	$(TCC) $(CFLAGS) -o build/langc $(SRC) build/domain.c

build/fronttool: $(FRONT_TOOL) $(HEADERS)
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/fronttool $(FRONT_TOOL)

build/checktool: $(CHECK_TOOL) src/main.c $(HEADERS)
	$(TCC) $(CFLAGS) -o build/checktool $(CHECK_TOOL)

check-clang: build/domain.c
	$(CC) $(CLANG_FLAGS) $(SRC) build/domain.c
	$(CC) $(CLANG_FLAGS) $(FRONT_TOOL)
	$(CC) $(CLANG_FLAGS) $(CHECK_TOOL)

check: build/langc build/fronttool build/checktool check-clang
	sh test/gate.sh
	sh test/review.sh
	build/fronttool
	build/checktool

clean:
	rm -rf build
