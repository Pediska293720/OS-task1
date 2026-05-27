CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC -g

all: librc4.so secure_copy

rc4.o: rc4.c
	$(CC) $(CFLAGS) -c $< -o $@

librc4.so: rc4.o
	$(CC) -shared $^ -o $@

caesar.o: caesar.c
	$(CC) $(CFLAGS) -c $< -o $@

libcaesar.so: caesar.o
	$(CC) -shared $^ -o $@

secure_copy: secure_copy.c
	$(CC) $(CFLAGS:-fPIC=) -o $@ $< -pthread -ldl

clean: 
	rm -f *.o *.so secure_copy

install: 
	sudo cp librc4.so /usr/local/lib/
	sudo ldconfig



