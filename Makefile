# SRedird base makefile
# Supplied by Kevin Bertram (kevin@cate.com.au)

CC=gcc
CFLAGS=-O3 -pipe -fomit-frame-pointer
WFLAGS=-Wall -W -Wshadow -Wpointer-arith -Wwrite-strings -pedantic

SRC=sredird.c

sredird:	sredird.c
	$(CC) $(CFLAGS) $(WFLAGS) -o sredird $(SRC)

clean:
	rm -f sredird
