#pragma once

#include <string>
#include <map>
#include <vector>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>

#define DEFAULT_MIME_TYPE "application/octet-stream"
#define DIRECTORY_MIME_TYPE "application/x-directory"
#define MAX_KEYS_PER_DIR_REQUEST 200

std::string trim_spaces(const std::string &s);
std::string trim_quotes(const std::string &s);
bool in_directory(const char *path, const char *dir);
unsigned long num(std::string value);
unsigned long long longnum(std::string value);
int create_tempfile();

class cmp_ignore_case {
    public:
        bool operator ()(const std::string &a, const std::string &b) {
            return strcasecmp(a.c_str(), b.c_str()) < 0;
        }
};

typedef std::map<std::string, std::string, cmp_ignore_case> mimes_t;
typedef std::vector<std::string> stringlist;

extern pthread_mutex_t global_lock;
extern pthread_t flush_thread;
extern bool flush_shutdown;
extern mimes_t mimeTypes;
extern time_t readwrite_timeout;
extern long connect_timeout;
extern int retries;
extern int writeback_delay;
extern std::string acl;
extern std::string private_acl;
extern std::string public_acl;
extern std::string bucket;
extern std::string AWSAccessKeyId;
extern std::string AWSSecretAccessKey;
extern std::string host;
extern std::string attr_cache;
extern std::string dir_cache;
extern std::string dir_cache_reset;
extern std::string writeback_cache;
extern mode_t root_mode;
