CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC

all: libcaesar.so secure_copy

caesar.o: caesar.c
	$(CC) $(CFLAGS) -c $< -o $@

libcaesar.so: caesar.o
	$(CC) -shared $^ -o $@

secure_copy: secure_copy.c
	$(CC) $(CFLAGS:-fPIC=) -o $@ $< -pthread -ldl

clean: 
	rm -f *.o *.so secure_copy

install: 
	sudo cp libcaesar.so /usr/local/lib/
	sudo ldconfig



