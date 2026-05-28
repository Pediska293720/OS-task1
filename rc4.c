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

typedef struct {
    uint8_t s[SBOX_SIZE];
    uint8_t i;
    uint8_t j;
} rc4_state_t;

//Key Scheduling Algorithm - перемешиваем S-блок для дальнецшего шифрования
static void rc4_ksa(const uint8_t *key, size_t keylen, rc4_state_t *state) {
    for (int i = 0; i < SBOX_SIZE; i++) {
        state->s[i] = i;
    }
    
    uint8_t j = 0;
    for (int i = 0; i < SBOX_SIZE; i++) {
        j = j + state->s[i] + key[i % keylen];
        uint8_t temp = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = temp;
    }
    
    state->i = 0;
    state->j = 0;
    //инициализируем счетчики для PRGA нулями
}
//Pseudo-Random Generation Algorithm - возвращает "случайный" байт S-блока, при каждом запуске разный
static uint8_t rc4_prga_byte(rc4_state_t *state) {
    state->i++;
    state->j += state->s[state->i];
    
    uint8_t temp = state->s[state->i];
    state->s[state->i] = state->s[state->j];
    state->s[state->j] = temp;
    
    return state->s[(state->s[state->i] + state->s[state->j]) & 0xFF]; //обрезаем до одного байта 0xFF
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
    
    rc4_state_t state;
    rc4_ksa(full_key, full_key_len, &state);
    
    uint8_t* src_bytes = (uint8_t*)src;
    uint8_t* dst_bytes = (uint8_t*)dst;
    
    for (int i = 0; i < len; i++) {
        dst_bytes[i] = src_bytes[i] ^ rc4_prga_byte(&state);
    }
    
    memset(&state, 0, sizeof(rc4_state_t));
    memset(full_key, 0, full_key_len);
    free(full_key);
    
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
}