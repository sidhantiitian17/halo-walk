# HALO-Walk native pieces. `make` builds the in-process calm-mode sentinel (halo/libhalo_sentinel.so).
# The controller falls back to the pure-Python calm path (and logs it) if the library is missing or fails to load.
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fPIC -pthread
LIB = halo/libhalo_sentinel.so

all: $(LIB)

$(LIB): halo/csrc/sentinel.c
	$(CC) $(CFLAGS) -shared -o $@ $< -lm

clean:
	rm -f $(LIB)

.PHONY: all clean
