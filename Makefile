# Builds the tcc-wasm kit with TinyCC. See README.md.
TCC ?= tcc
CC ?= cc
CFLAGS = -std=c99 -Wall -Werror -Isrc
CLANG_FLAGS = -std=c99 -Wall -Wextra -Wswitch-enum -Werror -fsyntax-only -Isrc
FRONT = src/front/base.c src/front/lexer.c src/front/parser.c src/front/fmt.c src/front/front.c src/front/eval.c src/front/check.c src/front/lower.c src/front/poseidon2.c src/front/sha512.c src/front/ed25519.c src/front/tfhe.c src/front/fhe.c src/front/tshare.c src/front/squash.c
TARGET = src/wasm.c
SRC = src/main.c $(FRONT) $(TARGET)
FRONT_TOOL = test/fronttool.c $(filter-out src/front/front.c src/front/lower.c,$(FRONT))
CHECK_TOOL = test/checktool.c $(FRONT) src/front/tdec.c src/front/tkeygen.c $(TARGET) build/domain.c
SQUASH_TOOL = test/squashtool.c src/front/squash.c src/front/tdec.c src/front/tfhe.c src/front/tshare.c src/front/sha512.c
MPC_TOOL = test/mpctool.c src/front/tkeygen.c src/front/squash.c src/front/tdec.c src/front/fhe.c src/front/tfhe.c src/front/tshare.c src/front/sha512.c
HEADERS = $(wildcard src/*.h src/front/*.h)

.PHONY: build check check-clang check-squash check-mpc clean

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

build/squashtool: $(SQUASH_TOOL) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -O2 -o build/squashtool $(SQUASH_TOOL)

build/mpctool: $(MPC_TOOL) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -O2 -o build/mpctool $(MPC_TOOL)

check-clang: build/domain.c
	$(CC) $(CLANG_FLAGS) $(SRC) build/domain.c
	$(CC) $(CLANG_FLAGS) $(FRONT_TOOL)
	$(CC) $(CLANG_FLAGS) $(CHECK_TOOL)
	$(CC) $(CLANG_FLAGS) $(SQUASH_TOOL)
	$(CC) $(CLANG_FLAGS) $(MPC_TOOL)

check: build/langc build/fronttool build/checktool check-clang
	sh test/gate.sh
	sh test/review.sh
	build/fronttool
	build/checktool

# The squash PBS rows (the 812 MB squash BSK, cc -O2): not in check (Q-S6-13).
check-squash: build/squashtool
	build/squashtool

# The MPC key set rows (the 5 parties make all the keys, cc -O2): not in check (Q-S6-17).
check-mpc: build/mpctool
	build/mpctool

clean:
	rm -rf build
