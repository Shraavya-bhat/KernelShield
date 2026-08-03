CC = gcc

SRC = src/main.c

TARGET = build/kernelshield

CFLAGS = -Wall -Wextra -O2

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p build
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -rf build

.PHONY: all clean
