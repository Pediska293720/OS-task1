#include "rc4.h"
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

#define SBOX_SIZE 256

static unsigned char* secure_master_key = NULL;
static size_t master_key_len = 0;
static size_t page_size = 0;

static pthread_mutex_t encryption_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint8_t* secure_sbox = NULL;
static size_t sbox_page_size = 0;
static pthread_mutex_t sbox_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    uint8_t s[SBOX_SIZE];
    uint8_t i;
    uint8_t j;
} rc4_state_t;

static void rc4_ksa_secure(const uint8_t *key, size_t keylen) {
    pthread_mutex_lock(&sbox_mutex);
    
    if (mprotect(secure_sbox, sbox_page_size, PROT_WRITE) == -1) {
        pthread_mutex_unlock(&sbox_mutex);
        return;
    }
    
    for (int i = 0; i < SBOX_SIZE; i++) {
        secure_sbox[i] = i;
    }
    
    uint8_t j = 0;
    for (int i = 0; i < SBOX_SIZE; i++) {
        j = j + secure_sbox[i] + key[i % keylen];
        uint8_t temp = secure_sbox[i];
        secure_sbox[i] = secure_sbox[j];
        secure_sbox[j] = temp;
    }
    
    mprotect(secure_sbox, sbox_page_size, PROT_NONE);
    pthread_mutex_unlock(&sbox_mutex);
}

static uint8_t rc4_prga_byte_secure(uint8_t *i_ptr, uint8_t *j_ptr) {
    pthread_mutex_lock(&sbox_mutex);
    
    if (mprotect(secure_sbox, sbox_page_size, PROT_READ | PROT_WRITE) == -1) {
        pthread_mutex_unlock(&sbox_mutex);
        return 0;
    }
    
    uint8_t i = *i_ptr;
    uint8_t j = *j_ptr;
    
    i++;
    j += secure_sbox[i];
    
    uint8_t temp = secure_sbox[i];
    secure_sbox[i] = secure_sbox[j];
    secure_sbox[j] = temp;
    
    uint8_t result = secure_sbox[(secure_sbox[i] + secure_sbox[j]) & 0xFF];
    
    *i_ptr = i;
    *j_ptr = j;
    
    mprotect(secure_sbox, sbox_page_size, PROT_NONE);
    pthread_mutex_unlock(&sbox_mutex);
    
    return result;
}

static int init_secure_sbox(void) {
    sbox_page_size = sysconf(_SC_PAGESIZE);
    if (sbox_page_size == 0) sbox_page_size = 4096;
    
    secure_sbox = mmap(NULL, sbox_page_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (secure_sbox == MAP_FAILED) {
        secure_sbox = NULL;
        return -1;
    }
    return 0;
}

static void cleanup_secure_sbox(void) {
    if (secure_sbox == NULL) return;
    
    pthread_mutex_lock(&sbox_mutex);
    mprotect(secure_sbox, sbox_page_size, PROT_READ | PROT_WRITE);
    memset(secure_sbox, 0, sbox_page_size);
    munmap(secure_sbox, sbox_page_size);
    secure_sbox = NULL;
    pthread_mutex_unlock(&sbox_mutex);
}

static int get_master_key(uint8_t* buffer, size_t* len) {
    if (secure_master_key == NULL) return -1;
    if (mprotect(secure_master_key, page_size, PROT_READ) == -1) {
        return -1;
    }
    
    *len = master_key_len;
    memcpy(buffer, secure_master_key, master_key_len);
    
    mprotect(secure_master_key, page_size, PROT_NONE);
    return 0;
}

static int set_master_key(const uint8_t* key, size_t len) {
    if (secure_master_key == NULL) return -1;
    if (len > page_size) {
        len = page_size;
    }
    
    if (mprotect(secure_master_key, page_size, PROT_WRITE) == -1) {
        return -1;
    }
    
    memcpy(secure_master_key, key, len);
    master_key_len = len;
    
    if (len < page_size) {
        memset(secure_master_key + len, 0, page_size - len);
    }
    
    mprotect(secure_master_key, page_size, PROT_NONE);
    return 0;
}

void rc4_crypt_with_salt(void* src, void* dst, int len, const uint8_t* salt, size_t salt_len) {
    if (src == NULL || dst == NULL || len <= 0) {
        return;
    }
    
    pthread_mutex_lock(&encryption_mutex);
    
    uint8_t stored_key[SBOX_SIZE];
    size_t stored_key_len = 0;
    
    if (get_master_key(stored_key, &stored_key_len) != 0 || stored_key_len == 0) {
        pthread_mutex_unlock(&encryption_mutex);
        return;
    }
    
    size_t full_key_len = stored_key_len + salt_len;
    uint8_t* full_key = malloc(full_key_len);
    
    if (full_key == NULL) {
        pthread_mutex_unlock(&encryption_mutex);
        return;
    }
    
    memcpy(full_key, stored_key, stored_key_len);
    memcpy(full_key + stored_key_len, salt, salt_len);
    memset(stored_key, 0, sizeof(stored_key));
    
    rc4_ksa_secure(full_key, full_key_len);
    
    uint8_t i = 0, j = 0;
    
    uint8_t* src_bytes = (uint8_t*)src;
    uint8_t* dst_bytes = (uint8_t*)dst;
    
    for (int pos = 0; pos < len; pos++) {
        dst_bytes[pos] = src_bytes[pos] ^ rc4_prga_byte_secure(&i, &j);
    }
    
    memset(full_key, 0, full_key_len);
    free(full_key);
    
    pthread_mutex_lock(&sbox_mutex);
    if (mprotect(secure_sbox, sbox_page_size, PROT_WRITE) == 0) {
        memset(secure_sbox, 0, SBOX_SIZE);
        mprotect(secure_sbox, sbox_page_size, PROT_NONE);
    }
    pthread_mutex_unlock(&sbox_mutex);
    
    pthread_mutex_unlock(&encryption_mutex);
}

int init_secure_key_storage(void) {
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096;
    
    secure_master_key = mmap(NULL, page_size, PROT_NONE, 
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (secure_master_key == MAP_FAILED) {
        secure_master_key = NULL;
        return -1;
    }
    
    if (init_secure_sbox() != 0) {
        munmap(secure_master_key, page_size);
        secure_master_key = NULL;
        return -1;
    }
    
    master_key_len = 0;
    return 0;
}

int set_key(const char* key, size_t key_len) {
    if (key == NULL || key_len == 0) return -1;
    return set_master_key((const uint8_t*)key, key_len);
}

void cleanup_secure_key(void) {
    if (secure_master_key == NULL) return;
    
    mprotect(secure_master_key, page_size, PROT_READ | PROT_WRITE);
    memset(secure_master_key, 0, page_size);
    master_key_len = 0;
    
    munmap(secure_master_key, page_size);
    secure_master_key = NULL;
    
    cleanup_secure_sbox();
}