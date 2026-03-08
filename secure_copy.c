#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <glib.h>
#include <dlfcn.h>

#define BUFFER_SIZE 4096

static volatile int keep_running = 1;

void (*caesar)(void*, void*, int) = NULL;
void (*set_key)(char) = NULL;

typedef struct {
    unsigned char *data;
    int size;
} data_block_t;


typedef struct {
    GAsyncQueue *queue;
    int input_fd;
    int output_fd;
    int key;
    volatile int *running;
    int producer_done;
    pthread_mutex_t done_mutex;
    pthread_cond_t cond;
} thread_data_t;  


int load_caesar_library() {
    void *handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!handle) {
        printf("Ошибка загрузки libcaesar.so\n");
        return -1;
    }
    
    *(void**)(&caesar) = dlsym(handle, "caesar");
    *(void**)(&set_key) = dlsym(handle, "set_key");
    
    char *error = dlerror();
    if (error) {
        printf("Ошибка поиска символов\n");
        dlclose(handle);
        return -1;
    }
    
    return 0;
}


void* producer_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    unsigned char *read_buffer = malloc(BUFFER_SIZE);
    unsigned char *encrypted_buffer = malloc(BUFFER_SIZE);
    
    if (!read_buffer || !encrypted_buffer) {
        printf("Ошибка выделения памяти в producer\n");
        free(read_buffer);
        free(encrypted_buffer);
        return NULL;
    }
    set_key((char)data->key);
    
    while (*data->running) {
        ssize_t bytes_read = read(data->input_fd, read_buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            if (bytes_read < 0) {
                printf("Ошибка чтения файла\n");
            }
            break;
        }
        caesar(read_buffer, encrypted_buffer, bytes_read);

        data_block_t *block = malloc(sizeof(data_block_t));
        block->data = malloc(bytes_read);

        if (!block->data) {
            printf("Ошибка выделения памяти для данных блока\n");
            free(block);
            break;
        }
        memcpy(block->data, encrypted_buffer, bytes_read);
        block->size = bytes_read;
        g_async_queue_push(data->queue, block);
    }
    
    pthread_mutex_lock(&data->done_mutex);
    data->producer_done = 1;
    pthread_cond_signal(&data->cond);  
    pthread_mutex_unlock(&data->done_mutex);
    free(read_buffer);
    free(encrypted_buffer);
    
    return NULL;
}


void* consumer_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    
    while (1) {
        data_block_t *block = g_async_queue_try_pop(data->queue);
        if (block){
            ssize_t bytes_written = write(data->output_fd, block->data, block->size);
            if (bytes_written != block->size) {
                if (bytes_written < 0) {
                    printf("Ошибка записи в файл\n");
                }
            }
            free(block->data);
            free(block);
        }
        else {
            pthread_mutex_lock(&data->done_mutex);
            if (data->producer_done && g_async_queue_length(data->queue) == 0) {
                pthread_mutex_unlock(&data->done_mutex);
                break;
            }

            if (*data->running && !data->producer_done) {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += 1;
                pthread_cond_timedwait(&data->cond, &data->done_mutex, &ts);
            }
            
            pthread_mutex_unlock(&data->done_mutex);
            if (!*data->running) {
                break;
            
            }
        }
    }

    while (1) {
        data_block_t *block = g_async_queue_try_pop(data->queue);
        if (!block) break;
        free(block->data);
        free(block);
    }
    return NULL;
}


void signal_handler(int sig) {
    if (sig == SIGINT) {
        keep_running = 0;
    }
}


int main(int argc, char *argv[]) {
    int ret = 0;
    if (argc != 4) {
        printf("Использование: %s <input_file> <output_file> <key>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], argv[2]) == 0) {
        printf("Ошибка: входной и выходной файлы не могут совпадать.\n");
        return 1;
    }

    if (load_caesar_library() != 0) {
        return 1;
    }
    
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        printf("Ошибка установки обработчика сигнала");
        return 1;
    }

    int input_fd = open(argv[1], O_RDONLY);
    if (input_fd == -1) {
        printf("Ошибка открытия входного файла '%s'\n", argv[1]);
        return 1;
    }

    int output_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd == -1) {
        printf("Ошибка открытия выходного файла '%s'\n", argv[2]);
        close(input_fd);
        return 1;
    }

    char key = argv[3][0];
    thread_data_t thread_data;  // Исправлено имя типа
    thread_data.input_fd = input_fd;
    thread_data.output_fd = output_fd;
    thread_data.key = key;
    thread_data.running = &keep_running;
    thread_data.producer_done = 0;

    thread_data.queue = g_async_queue_new();
    pthread_mutex_init(&thread_data.done_mutex, NULL);
    pthread_cond_init(&thread_data.cond, NULL);

    pthread_t producer, consumer;
    if (pthread_create(&producer, NULL, producer_thread, &thread_data) != 0) {
        ret = 1;
        goto cleanup;
    }
    if (pthread_create(&consumer, NULL, consumer_thread, &thread_data) != 0) {
        ret = 1;
        pthread_cancel(producer);
        pthread_join(producer, NULL);
        goto cleanup;
    }

    pthread_join(producer, NULL);
    pthread_join(consumer, NULL);

cleanup:
    close(input_fd);
    close(output_fd);
    
    if (thread_data.queue) {
        while (1) {
            data_block_t *block = g_async_queue_try_pop(thread_data.queue);
            if (!block) break;
            free(block->data);
            free(block);
        }
        g_async_queue_unref(thread_data.queue);
    }
    pthread_mutex_destroy(&thread_data.done_mutex);
    pthread_cond_destroy(&thread_data.cond);

    if (keep_running == 0) {
        printf("Операция прервана пользователем\n");
    } else {
        printf("Операция успешно завершена\n");
    }
    return ret;
}