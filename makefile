CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC
GLIB_FLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)

all: libcaesar.so caesar secure_copy

caesar.o: caesar.c
	$(CC) $(CFLAGS) -c $< -o $@

libcaesar.so: caesar.o
	$(CC) -shared $^ -o $@

caesar: main.c
	$(CC) main.c -o $@ -ldl

secure_copy: secure_copy.c
	$(CC) $(CFLAGS:-fPIC=) $(GLIB_FLAGS) -o $@ $< -pthread $(GLIB_LIBS) -ldl

test:
	echo "Hello, World! This is a test file." > test_input.txt
	./caesar ./libcaesar.so A test_input.txt test_encrypted.txt
	@cat test_encrypted.txt
	@echo ""
	./caesar ./libcaesar.so A test_encrypted.txt test_decrypted.txt
	@cat test_decrypted.txt
	@echo ""

install: 
	sudo cp libcaesar.so /usr/local/lib/
	sudo ldconfig

