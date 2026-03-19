#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BUFFER_SIZE 4096
#define TIMEOUT_SECONDS 5
#define COUNT_THREADS 3

static volatile int keep_running = 1;

void (*caesar)(void*, void*, int) = NULL;
void (*set_key)(char) = NULL;


typedef struct {
    char **input_files;            
    int total_files;               
    int *current_file_index;       
    char *output_dir;              
    int key;                       
    volatile int *running;         
    pthread_mutex_t *file_mutex;   
    FILE *log_file;                
    pthread_mutex_t *log_mutex;    
    int thread_id;                  
} thread_data_t;  

void get_timestamp(char *buffer, size_t size) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}

void log_operation(thread_data_t *data, const char *filename, const char *status) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    pthread_mutex_lock(data->log_mutex);
    fprintf(data->log_file, "[%s] Поток %d: %s - %s\n",
            timestamp, data->thread_id, filename, status);
    fflush(data->log_file);
    pthread_mutex_unlock(data->log_mutex);
}

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

char* get_next_file(thread_data_t *data) {
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += TIMEOUT_SECONDS;
    
    int lock_result = pthread_mutex_timedlock(data->file_mutex, &timeout);
    
    if (lock_result == ETIMEDOUT) {
        printf("Возможная взаимоблокировка: поток %d ожидает мьютекс >5 сек\n", 
               data->thread_id);
        return NULL;
    }
    
    if (lock_result != 0) {
        return NULL;
    }
    
    char *next_file = NULL;
    if (*data->current_file_index < data->total_files) {
        next_file = data->input_files[*data->current_file_index];
        (*data->current_file_index)++;
    }
    
    pthread_mutex_unlock(data->file_mutex);
    return next_file;
}

const char* get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    if (filename) return filename + 1;
    filename = strrchr(path, '\\');
    if (filename) return filename + 1;
    return path;
}


void* file_processor_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    
    unsigned char *read_buffer = malloc(BUFFER_SIZE);
    unsigned char *encrypted_buffer = malloc(BUFFER_SIZE);
    
    if (!read_buffer || !encrypted_buffer) {
        free(read_buffer);
        free(encrypted_buffer);
        return NULL;
    }
    
    set_key((char)data->key);
    
    while (*data->running) {
        char *input_file = get_next_file(data);
        if (!input_file) {
            pthread_mutex_lock(data->file_mutex);
            int all_processed = (*data->current_file_index >= data->total_files);
            pthread_mutex_unlock(data->file_mutex);
            
            if (all_processed) break;
            usleep(100000); 
            continue;
        }
        
        const char *base_filename = get_filename(input_file);
        
        char output_path[512];
        snprintf(output_path, sizeof(output_path), "%s/%s", 
                 data->output_dir, base_filename);
        
        int input_fd = open(input_file, O_RDONLY);
        if (input_fd == -1) {
            log_operation(data, input_file, "ОШИБКА: не удалось открыть файл");
            continue;
        }
        
        int output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd == -1) {
            log_operation(data, input_file, "ОШИБКА: не удалось создать выходной файл");
            close(input_fd);
            continue;
        }
        
        int success = 1;
        
        while (*data->running) {
            ssize_t bytes_read = read(input_fd, read_buffer, BUFFER_SIZE);
            if (bytes_read == 0) break;  
            if (bytes_read < 0) {
                success = 0;
                break;
            }
            
            caesar(read_buffer, encrypted_buffer, bytes_read);
            
            ssize_t bytes_written = write(output_fd, encrypted_buffer, bytes_read);
            if (bytes_written != bytes_read) {
                success = 0;
                break;
            }
        }
        
        close(input_fd);
        close(output_fd);
        
        if (success && *data->running) {
            log_operation(data, input_file, "УСПЕХ");
        } else if (!*data->running) {
            log_operation(data, input_file, "ПРЕРВАНО");
        } 
    }
    
    free(read_buffer);
    free(encrypted_buffer);
    return NULL;
}


void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nПолучен сигнал SIGINT. Завершение работы...\n");
        keep_running = 0;
    }
}


int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Использование: %s <file_1> ... <file_n> <output_dir> <key>\n", argv[0]);
        return 1;
    }

    if (load_caesar_library() != 0) {
        return 1;
    }

    int num_files = argc - 3;
    char *output_dir = argv[argc - 2];

    struct stat st = {0};
    if (stat(output_dir, &st) == -1) {
        mkdir(output_dir, 0700);
    }

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);


    pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
    int current_file_index = 0;  

    FILE *log_file = fopen("log.txt", "a");
    if (!log_file) {
        printf("Ошибка создания log.txt\n");
        return 1;
    }


    char key = atoi(argv[argc - 1]);

   char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    fflush(log_file);

    pthread_t threads[COUNT_THREADS];
    thread_data_t thread_data[COUNT_THREADS];

    for (int i = 0; i < COUNT_THREADS; i++) {
        thread_data[i].input_files = argv + 1;  
        thread_data[i].total_files = num_files;
        thread_data[i].current_file_index = &current_file_index;  
        thread_data[i].output_dir = output_dir;
        thread_data[i].key = key;
        thread_data[i].running = &keep_running;
        thread_data[i].file_mutex = &file_mutex;  
        thread_data[i].log_file = log_file;
        thread_data[i].log_mutex = &log_mutex;    
        thread_data[i].thread_id = i + 1;
        
        if (pthread_create(&threads[i], NULL, file_processor_thread, &thread_data[i]) != 0) {
            printf("Ошибка создания потока %d\n", i + 1);
            keep_running = 0;
            break;
        }
    }

    for (int i = 0; i < COUNT_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

     get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "=== Завершение %s ===\n\n", timestamp);
    fclose(log_file);

    pthread_mutex_destroy(&file_mutex);
    pthread_mutex_destroy(&log_mutex);

    return 0;
}