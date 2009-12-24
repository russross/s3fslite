#pragma once

#include <string>
#include <time.h>
#include <fcntl.h>

#define DEFAULT_MIME_TYPE "application/octet-stream"
#define DIRECTORY_MIME_TYPE "application/x-directory"
#define MD5_EMPTY "d41d8cd98f00b204e9800998ecf8427e"

std::string trim_spaces(const std::string &s);
std::string trim_quotes(const std::string &s);

class cmp_ignore_case {
    public:
        bool operator ()(const std::string &a, const std::string &b) {
            return strcasecmp(a.c_str(), b.c_str()) < 0;
        }
};

typedef std::map<std::string, std::string, cmp_ignore_case> mimes_t;
extern mimes_t mimeTypes;
extern time_t readwrite_timeout;
extern long connect_timeout;
extern int retries;
extern std::string default_acl;
extern std::string private_acl;
extern std::string public_acl;
extern std::string bucket;
extern std::string AWSAccessKeyId;
extern std::string AWSSecretAccessKey;
extern std::string host;
extern mode_t root_mode;
