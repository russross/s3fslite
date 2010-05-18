#include <string>
#include <map>
#include <vector>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "common.h"

// config parameters
std::string bucket;
std::string AWSAccessKeyId;
std::string AWSSecretAccessKey;
std::string host("http://%s.s3.amazonaws.com");
mode_t root_mode = 0755;
std::string attr_cache;
std::string dir_cache("false");
std::string dir_cache_reset("true");
std::string writeback_cache("/tmp");
int retries = 2;
long connect_timeout = 2;
time_t readwrite_timeout = 10;
int writeback_delay = 5;

// private, public-read, public-read-write, authenticated-read
std::string acl;
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
    // create the name template for the temp file
    std::string tmpname(writeback_cache);
    if (tmpname.size() == 0)
        tmpname = "/tmp";
    if (tmpname[tmpname.size() - 1] != '/')
        tmpname += "/";
    tmpname += "s3fslite.XXXXXX";

    char *localname = new char[tmpname.size() + 1];
    strcpy(localname, tmpname.c_str());

    // create a temporary file
    int fd = mkstemp(localname);
    if (fd < 0) {
        delete[] localname;
        throw -errno;
    }

    // unlink it immediately so it will be cleaned up when closed
    if (unlink(localname) < 0) {
        close(fd);
        delete[] localname;
        throw -errno;
    }

    delete[] localname;
    return fd;
}
