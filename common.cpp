#include <string>
#include <map>
#include <vector>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include "common.h"

// config parameters
std::string bucket;
std::string AWSAccessKeyId;
std::string AWSSecretAccessKey;
std::string host("http://s3.amazonaws.com");
mode_t root_mode = 0755;
std::string attr_cache;
int retries = 2;
long connect_timeout = 2;
time_t readwrite_timeout = 10;

// private, public-read, public-read-write, authenticated-read
std::string default_acl;
std::string private_acl("private");
std::string public_acl("public-read");

pthread_mutex_t global_lock;

pthread_t flush_thread;
bool flush_shutdown;

mimes_t mimeTypes;

// fd -> flags
static std::string SPACES(" \t\r\n");
static std::string QUOTES("\"");

std::string trim_spaces(const std::string &s) {
    std::string::size_type start(s.find_first_not_of(SPACES));
    std::string::size_type end(s.find_last_not_of(SPACES));
    if (start == std::string::npos || end == std::string::npos)
        return "";
    return s.substr(start, end + 1 - start);
}

std::string trim_quotes(const std::string &s) {
    std::string::size_type start(s.find_first_not_of(QUOTES));
    std::string::size_type end(s.find_last_not_of(QUOTES));
    if (start == std::string::npos || end == std::string::npos)
        return "";
    return s.substr(start, end + 1 - start);
}

unsigned long num(std::string value) {
    return strtoul(value.c_str(), NULL, 10);
}

unsigned long long longnum(std::string value) {
    return strtoull(value.c_str(), NULL, 10);
}

int create_tempfile() {
    char localname[32];
    strcpy(localname, "/tmp/s3fs.XXXXXX");
    int fd = mkstemp(localname);
    if (fd < 0)
        throw -errno;
    if (unlink(localname) < 0) {
        close(fd);
        throw -errno;
    }
    return fd;
}

