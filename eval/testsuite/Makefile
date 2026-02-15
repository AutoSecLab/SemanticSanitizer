CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

SRCS := $(wildcard benchmark-*.c)
BINS := $(SRCS:.c=)

all: $(BINS)

%: %.c benchmark.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS)

.PHONY: all clean
