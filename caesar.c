#include "caesar.h"
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

static unsigned char* secure_key_ptr = NULL;
static size_t page_size = 4096;
pthread_mutex_t encryption_mutex = PTHREAD_MUTEX_INITIALIZER;

int init_secure_key_storage(void) {
    secure_key_ptr = mmap(NULL, page_size, PROT_NONE, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (secure_key_ptr == MAP_FAILED) {
        secure_key_ptr = NULL;
        return -1;
    }

    return 0;
}

int set_key(char key){
    if (secure_key_ptr == NULL) return -1;
    
    mprotect(secure_key_ptr, page_size, PROT_WRITE);
    
    secure_key_ptr[0] = (unsigned char)key;

    mprotect(secure_key_ptr, page_size, PROT_NONE);
    
    return 0;
}

// #define SIMULATE_SEGFAULT yes
static unsigned char get_key(void) {
    if (secure_key_ptr == NULL) return 0;
    #ifndef SIMULATE_SEGFAULT
    mprotect(secure_key_ptr, page_size, PROT_READ);
    #endif

    unsigned char key = secure_key_ptr[0];

    mprotect(secure_key_ptr, page_size, PROT_NONE);
    
    return key;
}

void cleanup_secure_key(void) {
    if (secure_key_ptr == NULL) return;
    
    mprotect(secure_key_ptr, page_size, PROT_READ | PROT_WRITE);
    
    memset(secure_key_ptr, 0, page_size);
    
    munmap(secure_key_ptr, page_size);
    secure_key_ptr = NULL;
}

void caesar(void* src, void* dst, int len){
    unsigned char* src_bytes = (unsigned char*)src;
    unsigned char* dst_bytes = (unsigned char*)dst;

    pthread_mutex_lock(&encryption_mutex);
    unsigned char c_key = get_key();

    for (int i = 0; i < len; i++){
        dst_bytes[i] = src_bytes[i] ^ c_key; 
    }
    pthread_mutex_unlock(&encryption_mutex);
}



