CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC

cesare:
	$(CC) main.c -o cesare

lib:
	$(CC) $(CFLAGS) -c cesare.c -o cesare.o
	$(CC) $(CFLAGS) -shared cesare.c -o cesarelib.so



install: 
	sudo cp cesarelib.so /usr/local/lib/

