#pragma once

#include <string>
#include <vector>
#include <stdio.h>
#include <curl/curl.h>

#include "fileinfo.h"

#define MAX_KEYS_PER_DIR_REQUEST 200
typedef std::vector<std::string> stringlist;

int create_tempfile();

#define failif(e) do { \
    int result = (e); \
    if (result != 0) \
        throw result; \
} while (0)

class S3request {
    private:
        S3request(std::string path, std::string query = "");
        void add_header(const std::string &s);
        void sign_request(std::string method, std::string content_md5,
                std::string content_type, std::string date);
        void execute();

    public:
        CURL *curl;
        time_t last_time;
        double dlnow;
        double ulnow;
        curl_slist *headers;
        std::string resource;
        FILE *fp;

        ~S3request();

        static Fileinfo *get_fileinfo(std::string path);
        static void set_fileinfo(std::string path, Fileinfo *info);
        static int get_file(std::string path, Fileinfo *info);
        static void put_file(Fileinfo *info, int fd);
        static void remove(std::string path);
        static int get_directory(std::string path, std::string &marker,
                stringlist &result, int max_entries = MAX_KEYS_PER_DIR_REQUEST);
};
