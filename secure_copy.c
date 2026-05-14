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
#define WORKERS_COUNT 4

static volatile int keep_running = 1;

void (*caesar)(void*, void*, int) = NULL;
int (*set_key)(char) = NULL;
int (*init_secure_key_storage)(void) = NULL;
void (*cleanup_secure_key)(void) = NULL;

int (*test_key_protection)(void) = NULL;        // ДОБАВИТЬ
void (*print_protection_status)(void) = NULL;

typedef struct {
    struct timespec start_time;
    struct timespec end_time;
    double total_time_sec;
    double avg_time_per_file_sec;
    int files_processed;
} performance_stats_t;

typedef struct {
    char **input_files;            
    int total_files;               
    int *current_file_index;       
    char *output_dir;                               
    volatile int *running;         
    pthread_mutex_t *file_mutex;   
    FILE *log_file;                
    pthread_mutex_t *log_mutex;    
    int thread_id;
    performance_stats_t *thread_stats;
} thread_data_t;  

void get_timestamp(char *buffer, size_t size) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}

void log_operation(FILE *log_file, pthread_mutex_t *log_mutex, int thread_id, 
                   const char *filename, const char *status) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (log_mutex){
        pthread_mutex_lock(log_mutex);
    }
    fprintf(log_file, "[%s] Поток %d: %s - %s\n",
            timestamp, thread_id, filename, status);
    fflush(log_file);
    if (log_mutex){
        pthread_mutex_unlock(log_mutex);
    }
}

int load_caesar_library() {
    void *handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!handle) {
        printf("Ошибка загрузки libcaesar.so\n");
        return -1;
    }
    
    *(void**)(&caesar) = dlsym(handle, "caesar");
    *(void**)(&set_key) = dlsym(handle, "set_key");
    *(void**)(&init_secure_key_storage) = dlsym(handle, "init_secure_key_storage");
    *(void**)(&cleanup_secure_key) = dlsym(handle, "cleanup_secure_key"); 


    *(void**)(&test_key_protection) = dlsym(handle, "test_key_protection");        // ДОБАВИТЬ
    *(void**)(&print_protection_status) = dlsym(handle, "print_protection_status"); // ДОБАВИТЬ

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

int process_single_file(const char *input_file, const char *output_dir, 
                        FILE *log_file, pthread_mutex_t *log_mutex, 
                        int thread_id, struct timespec *file_start, 
                        struct timespec *file_end){
    clock_gettime(CLOCK_MONOTONIC, file_start);
    
    const char *base_filename = get_filename(input_file);
    char output_path[512];
    snprintf(output_path, sizeof(output_path), "%s/%s", output_dir, base_filename);
    
    int input_fd = open(input_file, O_RDONLY);
    if (input_fd == -1) {
        log_operation(log_file, log_mutex, thread_id, input_file, "ОШИБКА: не удалось открыть файл");
        return -1;
    }
    
    int output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd == -1) {
        log_operation(log_file, log_mutex, thread_id, input_file, "ОШИБКА: не удалось создать выходной файл");
        close(input_fd);
        return -1;
    }

    unsigned char *read_buffer = malloc(BUFFER_SIZE);
    unsigned char *encrypted_buffer = malloc(BUFFER_SIZE);

    if (!read_buffer || !encrypted_buffer) {
        free(read_buffer);
        free(encrypted_buffer);
        close(input_fd);
        close(output_fd);
        return -1;
    }

    int success = 1;

    while (1) {
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

    free(read_buffer);
    free(encrypted_buffer);
    close(input_fd);
    close(output_fd);
    
    clock_gettime(CLOCK_MONOTONIC, file_end);
    
    if (success) {
        log_operation(log_file, log_mutex, thread_id, input_file, "УСПЕХ");
        return 0;
    } else {
        log_operation(log_file, log_mutex, thread_id, input_file, "ОШИБКА");
        return -1;
    }
}

void* file_processor_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    
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
        
        struct timespec file_start, file_end;
        int result = process_single_file(input_file, data->output_dir,
                                        data->log_file, data->log_mutex,
                                        data->thread_id, &file_start, &file_end);
        
        if (result == 0 && data->thread_stats) {
            double file_time = (file_end.tv_sec - file_start.tv_sec) +
                             (file_end.tv_nsec - file_start.tv_nsec) / 1e9;
        
            data->thread_stats->total_time_sec += file_time;
            data->thread_stats->files_processed++;
        }
    }   
    return NULL;
}

void run_sequential_mode(char **input_files, int num_files, char *output_dir, 
                         FILE *log_file, performance_stats_t *stats) {
    clock_gettime(CLOCK_MONOTONIC, &stats->start_time);
    
    double total_file_time = 0.0;
    stats->files_processed = 0;
    
    for (int i = 0; i < num_files && keep_running; i++) {
        struct timespec file_start, file_end;
        int result = process_single_file(input_files[i], output_dir,
                                         log_file, NULL, 0, &file_start, &file_end);
        
        if (result == 0) {
            double file_time = (file_end.tv_sec - file_start.tv_sec) +
                             (file_end.tv_nsec - file_start.tv_nsec) / 1e9;
            total_file_time += file_time;
            stats->files_processed++;
            printf("Файл %d/%d обработан за %.3f сек\n", 
                   i + 1, num_files, file_time);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &stats->end_time);
    stats->total_time_sec = (stats->end_time.tv_sec - stats->start_time.tv_sec) +
                           (stats->end_time.tv_nsec - stats->start_time.tv_nsec) / 1e9;
    
    if (stats->files_processed > 0) {
        stats->avg_time_per_file_sec = total_file_time / stats->files_processed;
    } 
    else {
        stats->avg_time_per_file_sec = 0;
    }
}

void run_parallel_mode(char **input_files, int num_files, char *output_dir, 
                       FILE *log_file, performance_stats_t *stats) {
    pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
    int current_file_index = 0;
    
    pthread_t workers[WORKERS_COUNT];
    thread_data_t thread_data[WORKERS_COUNT];
    
    performance_stats_t thread_stats[WORKERS_COUNT];
    
    clock_gettime(CLOCK_MONOTONIC, &stats->start_time);
    
    for (int i = 0; i < WORKERS_COUNT; i++) {
        memset(&thread_stats[i], 0, sizeof(performance_stats_t));
        
        thread_data[i].input_files = input_files;
        thread_data[i].total_files = num_files;
        thread_data[i].current_file_index = &current_file_index;
        thread_data[i].output_dir = output_dir;
        thread_data[i].running = &keep_running;
        thread_data[i].file_mutex = &file_mutex;
        thread_data[i].log_file = log_file;
        thread_data[i].log_mutex = &log_mutex;
        thread_data[i].thread_id = i + 1;
        thread_data[i].thread_stats = &thread_stats[i];
        
        if (pthread_create(&workers[i], NULL, file_processor_thread, &thread_data[i]) != 0) {
            printf("Ошибка создания потока %d\n", i + 1);
            keep_running = 0;
        }
    }
    
    for (int i = 0; i < WORKERS_COUNT; i++) {
        pthread_join(workers[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &stats->end_time);
    stats->total_time_sec = (stats->end_time.tv_sec - stats->start_time.tv_sec) +
                           (stats->end_time.tv_nsec - stats->start_time.tv_nsec) / 1e9;
    
    double total_processing_time = 0;
    stats->files_processed = 0;
    for (int i = 0; i < WORKERS_COUNT; i++) {
        total_processing_time += thread_stats[i].total_time_sec;
        stats->files_processed += thread_stats[i].files_processed;
    }
    
    if (stats->files_processed > 0) {
        stats->avg_time_per_file_sec = stats->total_time_sec / stats->files_processed;
    } else {
        stats->avg_time_per_file_sec = 0;
    }
    
    pthread_mutex_destroy(&file_mutex);
    pthread_mutex_destroy(&log_mutex);
}

void print_statistics(const char *mode_name, performance_stats_t *stats) {
    printf("\nРежим: %s\n", mode_name);
    printf("Обработано файлов: %d\n", stats->files_processed);
    printf("Общее время выполнения: %.3f сек\n", stats->total_time_sec);
    printf("Среднее время на файл: %.3f сек\n", stats->avg_time_per_file_sec);
}

void print_comparison(performance_stats_t *seq_stats, performance_stats_t *par_stats) {
    printf("\nПоследовательный режим:\n");
    printf("- Общее время (сек)      %20.3f \n", seq_stats->total_time_sec);
    printf("- Среднее время (сек)    %20.3f \n", seq_stats->avg_time_per_file_sec);
    printf("- Обработано файлов      %20d \n", seq_stats->files_processed);

    printf("Параллельный режим:\n");
    printf("- Общее время (сек)      %20.3f \n", par_stats->total_time_sec);
    printf("- Среднее время (сек)    %20.3f \n", par_stats->avg_time_per_file_sec);
    printf("- Обработано файлов      %20d \n", par_stats->files_processed);

    if (par_stats->total_time_sec > 0) {
        double speedup = seq_stats->total_time_sec / par_stats->total_time_sec;
        printf("\nУскорение параллельного режима: %.2fx\n", speedup);
        if (speedup > 1.0) {
            printf("Параллельный режим быстрее на %.1f%%\n", (speedup - 1.0) * 100);
        } else if (speedup < 1.0) {
            printf("Последовательный режим быстрее на %.1f%%\n", (1.0 - speedup) * 100);
        } else {
            printf("Режимы работают одинаково\n");
        }
    }
}

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nПолучен сигнал SIGINT. Завершение работы...\n");
        keep_running = 0;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Использование: %s --mode=<sequential|parallel|auto> <file_1> ... <file_n> <output_dir> <key>\n", argv[0]);
        return 1;
    }

    if (load_caesar_library() != 0) {
        return 1;
    }
    
    char *mode_str = NULL;
    if (strncmp(argv[1], "--mode=", 7) == 0) {
        mode_str = argv[1] + 7;
    } 
    else {
        printf("Ошибка: первый аргумент должен быть --mode=<sequential|parallel|auto>\n");
        return 1;
    }

    int num_files = argc - 4;
    char *output_dir = argv[argc - 2];
    char **input_files = argv + 2;
    
    char key = atoi(argv[argc - 1]);

    if (init_secure_key_storage() != 0) {
        printf("Ошибка инициализации защищенного хранилища ключа\n");
        return 1;
    }

    if (set_key(key) != 0) {
        printf("Ошибка установки ключа\n");
        cleanup_secure_key();
        return 1;
    }

    struct stat st = {0};
    if (stat(output_dir, &st) == -1) {
        mkdir(output_dir, 0700);
    }

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    FILE *log_file = fopen("log.txt", "a");
    if (!log_file) {
        printf("Ошибка создания log.txt\n");
        return 1;
    }
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "\n=== Новая сессия %s ===\n", timestamp);

    performance_stats_t seq_stats, par_stats;
    memset(&seq_stats, 0, sizeof(seq_stats));
    memset(&par_stats, 0, sizeof(par_stats));

    if (strcmp(mode_str, "sequential") == 0) {
        run_sequential_mode(input_files, num_files, output_dir, log_file, &seq_stats);
        print_statistics("ПОСЛЕДОВАТЕЛЬНЫЙ", &seq_stats);
    } 
    else if (strcmp(mode_str, "parallel") == 0) {
        run_parallel_mode(input_files, num_files, output_dir, log_file, &par_stats);
        print_statistics("ПАРАЛЛЕЛЬНЫЙ", &par_stats);
    }
    else if (strcmp(mode_str, "auto") == 0) {
        if (num_files < 5) {
            run_sequential_mode(input_files, num_files, output_dir, log_file, &seq_stats);
            print_statistics("ПОСЛЕДОВАТЕЛЬНЫЙ", &seq_stats);
            run_parallel_mode(input_files, num_files, output_dir, log_file, &par_stats);
        }
        else {
            run_parallel_mode(input_files, num_files, output_dir, log_file, &par_stats);
            print_statistics("ПАРАЛЛЕЛЬНЫЙ", &par_stats);
            run_sequential_mode(input_files, num_files, output_dir, log_file, &seq_stats);
        }
        print_comparison(&seq_stats, &par_stats);
    }
    
    else{
        printf("Ошибка: неизвестный режим '%s'. Используйте sequential, parallel или auto\n", mode_str);
        fclose(log_file);
        return 1;
    }

    cleanup_secure_key();
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "=== Завершение %s ===\n\n", timestamp);
    fclose(log_file);

    return 0;
}