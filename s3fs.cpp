/*
 * s3fslite - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
 *
 * Some parts Copyright 2009 Russ Ross <russ@russross.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#define FUSE_USE_VERSION 26

// C++ standard library
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stack>
#include <string>
#include <vector>
#include <algorithm>

// C and Unix libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>
#include <pthread.h>
#include <libgen.h>

// non-standard dependencies
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <fuse.h>
#include <sqlite3.h>

using namespace std;

#define MAX_KEYS_PER_DIR_REQUEST "200"
#define DEFAULT_MIME_TYPE "application/octet-stream"
#define MD5_EMPTY "d41d8cd98f00b204e9800998ecf8427e"

#define VERIFY(s) do { \
    int result = (s); \
    if (result != 0) \
        return result; \
} while (0)

#define Yikes(result) do { \
    syslog(LOG_ERR, "yikes[%s] line[%u]", strerror(result), __LINE__); \
    return result; \
} while (0)

// config parameters
string bucket;
string AWSAccessKeyId;
string AWSSecretAccessKey;
string host = "http://s3.amazonaws.com";
mode_t root_mode = 0755;

// if .size()==0 then local file cache is disabled
string use_cache;
string attr_cache;

// private, public-read, public-read-write, authenticated-read
string default_acl;
string private_acl("private");
string public_acl("public-read");

// -oretries=2
int retries = 2;

long connect_timeout = 2;
time_t readwrite_timeout = 10;


class auto_fd {
    int fd;
public:
    auto_fd(int fd): fd(fd) {}
    ~auto_fd() {
        close(fd);
    }
    int get() {
        return fd;
    }
};

template<typename T>
string str(T value) {
    stringstream tmp;
    tmp << value;
    return tmp.str();
}

#define SPACES " \t\r\n"

inline string trim_left (const string & s, const string & t = SPACES) {
    string d (s);
    return d.erase (0, s.find_first_not_of (t)) ;
}  // end of trim_left

inline string trim_right (const string & s, const string & t = SPACES) {
    string d (s);
    string::size_type i (d.find_last_not_of (t));
    if (i == string::npos)
        return "";
    else
        return d.erase (d.find_last_not_of (t) + 1) ;
}  // end of trim_right

inline string trim (const string & s, const string & t = SPACES) {
    string d (s);
    return trim_left (trim_right (d, t), t) ;
}  // end of trim

class auto_lock {
    pthread_mutex_t& lock;
public:
    auto_lock(pthread_mutex_t& lock): lock(lock) {
        pthread_mutex_lock(&lock);
    }
    ~auto_lock() {
        pthread_mutex_unlock(&lock);
    }
};

stack<CURL*> curl_handles;
pthread_mutex_t curl_handles_lock;

typedef pair<double, double> progress_t;
map<CURL*, time_t> curl_times;
map<CURL*, progress_t> curl_progress;

pthread_mutex_t *mutex_buf = NULL;

// http headers
typedef map<string, string> headers_t;

int get_headers(const char *path, headers_t &head);
int put_headers(const char *path, headers_t head);
int generic_put(const char *path, mode_t mode, int fd = -1);

const char hexAlphabet[] = "0123456789ABCDEF";

/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */
string urlEncode(const string &s) {
    string result;
    for (unsigned i = 0; i < s.length(); ++i) {
        if (s[i] == '/') // Note- special case for fuse paths...
            result += s[i];
        else if (isalnum(s[i]))
            result += s[i];
        else if (s[i] == '.' || s[i] == '-' || s[i] == '*' || s[i] == '_')
            result += s[i];
        else if (s[i] == ' ')
            result += '+';
        else {
            result += "%";
            result += hexAlphabet[static_cast<unsigned char>(s[i]) / 16];
            result += hexAlphabet[static_cast<unsigned char>(s[i]) % 16];
        }
    }
    return result;
}

struct case_insensitive_compare_func {
    bool operator ()(const string &a, const string &b) {
        return strcasecmp(a.c_str(), b.c_str()) < 0;
    }
};

typedef map<string, string, case_insensitive_compare_func> mimes_t;

mimes_t mimeTypes;

// fd -> flags
typedef map<int, int> s3fs_descriptors_t;
s3fs_descriptors_t s3fs_descriptors;
pthread_mutex_t s3fs_descriptors_lock;

/**
 * @param s e.g., "index.html"
 * @return e.g., "text/html"
 */
string lookupMimeType(string s) {
    string result(DEFAULT_MIME_TYPE);
    string::size_type pos = s.find_last_of('.');
    if (pos != string::npos) {
        s = s.substr(1 + pos, string::npos);
    }
    mimes_t::const_iterator iter = mimeTypes.find(s);
    if (iter != mimeTypes.end())
        result = (*iter).second;
    return result;
}

// homegrown timeout mechanism
int my_curl_progress(void *clientp, double dltotal,
        double dlnow, double ultotal, double ulnow)
{
    CURL *curl = static_cast<CURL *>(clientp);

    time_t now = time(0);
    progress_t p(dlnow, ulnow);

    auto_lock lock(curl_handles_lock);

    // any progress?
    if (p != curl_progress[curl]) {
        // yes!
        curl_times[curl] = now;
        curl_progress[curl] = p;
    } else {
        // timeout?
        if (now - curl_times[curl] > readwrite_timeout)
            return CURLE_ABORTED_BY_CALLBACK;
    }

    return 0;
}

CURL *alloc_curl_handle() {
    CURL *curl;
    auto_lock lock(curl_handles_lock);
    if (curl_handles.size() == 0)
        curl = curl_easy_init();
    else {
        curl = curl_handles.top();
        curl_handles.pop();
    }
    curl_easy_reset(curl);
    long signal = 1;
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, signal);

    //  long timeout = 3600;
    //  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

    //###long seconds = 10;
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);

    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
    curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, my_curl_progress);
    curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, curl);
    time_t now = time(0);
    curl_times[curl] = now;
    curl_progress[curl] = progress_t(-1, -1);
    return curl;
}

void return_curl_handle(CURL *curl_handle) {
    if (curl_handle != 0) {
        auto_lock lock(curl_handles_lock);
        curl_handles.push(curl_handle);
        curl_times.erase(curl_handle);
        curl_progress.erase(curl_handle);
    }
}

class auto_curl {
    CURL* curl_handle;
public:
    auto_curl(): curl_handle(alloc_curl_handle()) {
    }
    ~auto_curl() {
        if (curl_handle != 0)
            return_curl_handle(curl_handle);
    }
    CURL* get() const {
        return curl_handle;
    }
    operator CURL*() const {
        return curl_handle;
    }
};

struct curl_multi_remove_handle_functor {
    CURLM *multi_handle;
    curl_multi_remove_handle_functor(CURLM *multi_handle):
        multi_handle(multi_handle) {}
    void operator()(CURL *curl_handle) {
        curl_multi_remove_handle(multi_handle, curl_handle);
        return_curl_handle(curl_handle);
    }
};

class auto_curl_multi {
    CURLM *multi_handle;
    vector<CURL *> curl_handles;
public:
    auto_curl_multi(): multi_handle(curl_multi_init()) {}
    ~auto_curl_multi() {
        curl_multi_cleanup(for_each(curl_handles.begin(), curl_handles.end(),
                    curl_multi_remove_handle_functor(multi_handle)).
                multi_handle);
    }
    CURLM *get() const {
        return multi_handle;
    }
    void add_curl(CURL *curl_handle) {
        curl_handles.push_back(curl_handle);
        curl_multi_add_handle(multi_handle, curl_handle);
    }
};

class auto_curl_slist {
    struct curl_slist *slist;
public:
    auto_curl_slist(): slist(0) {
    }
    ~auto_curl_slist() {
        curl_slist_free_all(slist);
    }
    struct curl_slist *get() const {
        return slist;
    }
    void append(const string &s) {
        slist = curl_slist_append(slist, s.c_str());
    }
};

/**
 * @return fuse return code
 */
int my_curl_easy_perform(CURL *curl, FILE *f = 0) {
    // 1 attempt + retries...
    int t = 1 + retries;
    while (t-- > 0) {
        if (f)
            rewind(f);
        CURLcode curlCode = curl_easy_perform(curl);
        if (curlCode == 0) {
            return 0;
        } else if (curlCode == CURLE_OPERATION_TIMEDOUT) {
#ifdef DEBUG
            syslog(LOG_INFO, "curl timeout");
#endif
        } else if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
            long responseCode;
            if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
                        &responseCode) != 0)
            {
                return -EIO;
            }
            if (responseCode == 404)
                return -ENOENT;

            syslog(LOG_ERR, "curl unexpected error code [%ld]", responseCode);

            if (responseCode < 500)
                return -EIO;
        } else {
            syslog(LOG_ERR, "curl error[%s]", curl_easy_strerror(curlCode));;
        }
#ifdef DEBUG
        syslog(LOG_INFO, "curl retrying...");
#endif
    }
    syslog(LOG_ERR, "curl giving up after %d tries", retries + 1);
    return -EIO;
}

string getAcl(mode_t mode) {
    if (default_acl != "")
        return default_acl;
    if (mode & S_IROTH)
        return public_acl;
    return private_acl;
}

//
// File info
//

class Fileinfo {
    public:
        string path;
        unsigned uid;
        unsigned gid;
        mode_t mode;
        time_t mtime;
        size_t size;
        string etag;

        Fileinfo(const char *path, struct stat *info, const char *etag);
        Fileinfo(const char *path, unsigned uid, unsigned gid,
                mode_t mode, time_t mtime, size_t size, const char *etag);
        void set(const char *path, unsigned uid, unsigned gid,
                mode_t mode, time_t mtime, size_t size, const char *etag);
        void updateHeaders(const char *target = 0);

        void toStat(struct stat *info);
};

class Attrcache {
    private:
        sqlite3 *conn;
        pthread_mutex_t lock;

    public:
        Attrcache(const char *bucket);
        Fileinfo get(const char *path);
        void set(const char *path, struct stat *info, const char *etag);
        void set(Fileinfo &info);
        void del(const char *path);
        ~Attrcache();
};

Attrcache *attrcache;

Fileinfo::Fileinfo(const char *path, unsigned uid, unsigned gid,
        mode_t mode, time_t mtime, size_t size, const char *etag)
{
    set(path, uid, gid, mode, mtime, size, etag);
}

Fileinfo::Fileinfo(const char *path, struct stat *info, const char *etag) {
    set(path, info->st_uid, info->st_gid, info->st_mode, info->st_mtime,
            info->st_size, etag);
}

void Fileinfo::set(const char *path, unsigned uid, unsigned gid,
    mode_t mode, time_t mtime, size_t size, const char *etag)
{
    this->path = path;
    this->uid = uid;
    this->gid = gid;
    this->mode = mode;
    this->mtime = mtime;
    this->size = size;
    this->etag = etag;
}

void Fileinfo::toStat(struct stat *info) {
    bzero(info, sizeof(struct stat));
    info->st_nlink = 1;
    info->st_uid = uid;
    info->st_gid = gid;
    info->st_mode = mode;
    info->st_mtime = mtime;
    info->st_size = size;
    if (S_ISREG(mode))
        info->st_blocks = info->st_size / 512 + 1;
}

void Fileinfo::updateHeaders(const char *target) {
    // special case: for the root, just update the cache
    if (path == "/") {
        attrcache->set(*this);
        return;
    }

    headers_t head;
    head["x-amz-copy-source"] = urlEncode("/" + bucket + path);
    head["x-amz-meta-uid"] = str(uid);
    head["x-amz-meta-gid"] = str(gid);
    head["x-amz-meta-mode"] = str(mode);
    head["x-amz-meta-mtime"] = str(mtime);
    head["Content-Length"] = str(size);
    if (mode & S_IFDIR)
        head["Content-Type"] = "application/x-directory";
    else if (mode & S_IFREG)
        head["Content-Type"] = lookupMimeType(path);
    else
        head["Content-Type"] = DEFAULT_MIME_TYPE;
    head["x-amz-metadata-directive"] = "REPLACE";

    attrcache->del(path.c_str());

    int result = put_headers(target ? target : path.c_str(), head);
    if (result != 0)
        throw result;

    // put the new name in the cache
    if (target)
        path = target;
    attrcache->set(*this);
}

Fileinfo get_fileinfo(const char *path) {
    // first check the cache
    try {
        Fileinfo result = attrcache->get(path);
        return result;
    } catch (int e) {
        // cache miss
    }

    // special case for /
    if (!strcmp(path, "/")) {
        Fileinfo result(path, 0, 0, root_mode | S_IFDIR, time(NULL), 0,
                MD5_EMPTY);

        // we'll even store it in the cache so rsync can update it
        attrcache->set(result);
        return result;
    }

    // do a header lookup
    headers_t head;

    int status = get_headers(path, head);

    // if we could not get the headers, assume it does not exist
    if (status)
        throw status;

    // fill in info based on header results
    unsigned mtime = strtoul(head["x-amz-meta-mtime"].c_str(), NULL, 10);
    if (mtime == 0) {
        // no mtime header? Parse the Last-Modified header instead
        // Last-Modified: Fri, 25 Sep 2009 22:24:38 GMT
        struct tm tm;
        strptime(head["Last-Modified"].c_str(),
                "%a, %d %b %Y %H:%M:%S GMT", &tm);
        mtime = mktime(&tm);
    }

    mode_t mode = strtoul(head["x-amz-meta-mode"].c_str(), NULL, 10);
    if (!(mode & S_IFMT)) {
        // missing file type: try to at least figure out if it is a directory
        if (head["Content-Type"] == "application/x-directory")
            mode |= S_IFDIR;
        else
            mode |= S_IFREG;
    }

    size_t size = strtoull(head["Content-Length"].c_str(), NULL, 10);
    unsigned uid = strtoul(head["x-amz-meta-uid"].c_str(), NULL, 10);
    unsigned gid = strtoul(head["x-amz-meta-gid"].c_str(), NULL, 10);

    string etag(trim(head["ETag"], "\""));
    Fileinfo result(path, uid, gid, mode, mtime, size, etag.c_str());

    // update the cache
    attrcache->set(result);

    return result;
}

//
// SQLite attribute caching
//
Attrcache::Attrcache(const char *bucket) {
    std::string name(attr_cache);
    if (name.size() > 0 && name[name.size() - 1] != '/')
        name += "/";
    name += bucket;
    name += ".sqlite";
    char **result;
    int rows;
    int columns;
    char *err;
    int status;

    pthread_mutex_init(&lock, NULL);
    auto_lock sync(lock);

    if (sqlite3_open(name.c_str(), &conn) != SQLITE_OK) {
        std::cerr << "Can't open database: " << name << ": " <<
            sqlite3_errmsg(conn) << std::endl;
        exit(-1);
    }

    // create the table if it does not already exist
    status = sqlite3_get_table(conn,
        "CREATE TABLE cache (\n"
        "    path VARCHAR(256) NOT NULL,\n"
        "    uid INTEGER,\n"
        "    gid INTEGER,\n"
        "    mode INTEGER,\n"
        "    mtime INTEGER,\n"
        "    size INTEGER,\n"
        "    etag VARCHAR(96),\n"
        "    PRIMARY KEY (path)\n"
        ")",
        &result, &rows, &columns, &err);

    if (status == SQLITE_OK)
        sqlite3_free_table(result);
    else
        sqlite3_free(err);
}

Attrcache::~Attrcache() {
    {
        auto_lock sync(lock);
        sqlite3_close(conn);
    }
    pthread_mutex_destroy(&lock);
}

Fileinfo Attrcache::get(const char *path) {
    char **data;
    int rows;
    int columns;
    char *err;
    char *query;

    auto_lock sync(lock);

    // perform the query
    query = sqlite3_mprintf(
        "SELECT uid, gid, mode, mtime, size, etag FROM cache WHERE path = '%q'",
        path);
    int status = sqlite3_get_table(conn, query, &data, &rows, &columns, &err);
    sqlite3_free(query);

    // error?
    if (status != SQLITE_OK) {
        syslog(LOG_ERR, "sqlite error[%s]", err);
        sqlite3_free(err);
        throw -1;
    }

    // no results?
    if (rows == 0) {
        sqlite3_free_table(data);
        throw -1;
    }

    // get the data from the second row
    Fileinfo result(
            path,
            strtoul(data[6], NULL, 10), // uid
            strtoul(data[7], NULL, 10), // gid
            strtoul(data[8], NULL, 10), // mode
            strtoul(data[9], NULL, 10), // mtime
            strtoul(data[10], NULL, 10), // size
            data[11]); // etag
    sqlite3_free_table(data);

    return result;
}

void Attrcache::set(const char *path, struct stat *info, const char *etag) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    // make sure there isn't an existing entry
    del(path);

    auto_lock sync(lock);

    query = sqlite3_mprintf(
        "INSERT INTO cache (path, uid, gid, mode, mtime, size, etag)\n"
        "VALUES ('%q', '%u', '%u', '%u', '%u', '%llu', '%q')",
        path,
        info->st_uid,
        info->st_gid,
        info->st_mode,
        info->st_mtime,
        info->st_size,
        etag);
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "set_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

void Attrcache::set(Fileinfo &info) {
    struct stat attr;
    info.toStat(&attr);
    set(info.path.c_str(), &attr, info.etag.c_str());
}

void Attrcache::del(const char *path) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    auto_lock sync(lock);

    query = sqlite3_mprintf(
        "DELETE FROM cache WHERE path = '%q'",
        path);
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "delete_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}


//
// File cache
//

typedef vector <unsigned char> bytes;

#define MAX_CACHE_ENTRIES 20
#define MAX_CACHE_FILE_SIZE 1024*1024*16

class Filecache {
    private:
        // path -> fileinfo

};

const EVP_MD *evp_md = EVP_sha1();

/**
 * Returns the current date
 * in a format suitable for a HTTP request header.
 */
string get_date() {
    char buf[100];
    time_t t = time(NULL);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
    return buf;
}

/**
 * Returns the Amazon AWS signature for the given parameters.
 *
 * @param method e.g., "GET"
 * @param content_type e.g., "application/x-directory"
 * @param date e.g., get_date()
 * @param resource e.g., "/pub"
 */
string calc_signature(string method, string content_type, string date,
        curl_slist* headers, string resource)
{
    string Signature;
    string StringToSign;
    StringToSign += method + "\n";
    StringToSign += "\n"; // md5
    StringToSign += content_type + "\n";
    StringToSign += date + "\n";
    int count = 0;

    while (headers) {
        if (strncmp(headers->data, "x-amz", 5) == 0) {
            count++;
            StringToSign += headers->data;
            StringToSign += 10; // linefeed
        }
        headers = headers->next;
    }
    StringToSign += resource;

    const void *key = AWSSecretAccessKey.data();
    int key_len = AWSSecretAccessKey.size();
    const unsigned char *d =
        reinterpret_cast<const unsigned char *>(StringToSign.data());
    int n = StringToSign.size();
    unsigned int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];

    HMAC(evp_md, key, key_len, d, n, md, &md_len);

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md, md_len);
    // (void) is to silence a warning
    (void) BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    Signature.resize(bptr->length - 1);
    memcpy(&Signature[0], bptr->data, bptr->length-1);

    BIO_free_all(b64);

    return Signature;
}

// libcurl callback
size_t readCallback(void *data, size_t blockSize, size_t numBlocks,
        void *userPtr)
{
    string *userString = static_cast<string *>(userPtr);
    size_t count = min((*userString).size(), blockSize * numBlocks);
    memcpy(data, (*userString).data(), count);
    (*userString).erase(0, count);
    return count;
}

// libcurl callback
size_t writeCallback(void* data, size_t blockSize, size_t numBlocks,
        void *userPtr)
{
    string *userString = static_cast<string *>(userPtr);
    (*userString).append(reinterpret_cast<const char *>(data),
            blockSize * numBlocks);
    return blockSize * numBlocks;
}

size_t header_callback(void *data, size_t blockSize, size_t numBlocks,
        void *userPtr)
{
    headers_t *headers = reinterpret_cast<headers_t *>(userPtr);
    string header(reinterpret_cast<char *>(data), blockSize * numBlocks);
    string key;
    stringstream ss(header);
    if (getline(ss, key, ':')) {
        string value;
        getline(ss, value);
        (*headers)[key] = trim(value);
    }
    return blockSize * numBlocks;
}

// safe variant of dirname
string mydirname(string path) {
    // dirname clobbers path so let it operate on a tmp copy
    return dirname(&path[0]);
}

// safe variant of basename
string mybasename(string path) {
    // basename clobbers path so let it operate on a tmp copy
    return basename(&path[0]);
}

// mkdir --parents
int mkdirp(const string &path, mode_t mode) {
    string base;
    string component;
    stringstream ss(path);
    while (getline(ss, component, '/')) {
        base += "/" + component;
        /*if (*/mkdir(base.c_str(), mode)/* == -1);
            return -1*/;
    }
    return 0;
}

/**
 * @return fuse return code
 * TODO return pair<int, headers_t>?!?
 */
int get_headers(const char *path, headers_t &head) {
#ifdef DEBUG
    syslog(LOG_INFO, "get_headers[%s]", path);
#endif

    string resource(urlEncode("/" + bucket + path));
    string url(host + resource);

    auto_curl curl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
    curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
    curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified

    headers_t responseHeaders;
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

    auto_curl_slist headers;
    string date = get_date();
    headers.append("Date: "+date);
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
            calc_signature("HEAD", "", date, headers.get(), resource));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

    VERIFY(my_curl_easy_perform((curl.get())));

    // at this point we know the file exists in s3

    for (headers_t::iterator iter = responseHeaders.begin();
            iter != responseHeaders.end(); ++iter)
    {
        string key = (*iter).first;
        string value = (*iter).second;
        head[key] = value;
//        if (key == "Content-Type")
//            head[key] = value;
//        if (key == "ETag")
//            head[key] = value;
//        if (key.substr(0, 5) == "x-amz")
//            head[key] = value;
    }

    return 0;
}

/**
 * get_local_fd
 *
 * Return the fd for a local copy of the given path.
 * Open the cached copy if available, otherwise download it
 * into the cache and return the result.
 */
int get_local_fd(const char *path) {
    string resource(urlEncode("/" + bucket + path));
    string url(host + resource);

    string baseName = mybasename(path);
    string resolved_path(use_cache + "/" + bucket);

    int fd = -1;

    string cache_path(resolved_path + path);

    headers_t responseHeaders;

    if (use_cache.size() > 0) {
        VERIFY(get_headers(path, responseHeaders));

        // ### TODO should really somehow obey flags here
        fd = open(cache_path.c_str(), O_RDWR);

        if (fd >= 0) {
            MD5_CTX c;
            if (MD5_Init(&c) != 1)
                Yikes(-EIO);
            int count;
            char buf[4096];
            while ((count = read(fd, buf, sizeof(buf))) > 0) {
                if (MD5_Update(&c, buf, count) != 1)
                    Yikes(-EIO);
            }
            unsigned char md[MD5_DIGEST_LENGTH];
            if (MD5_Final(md, &c) != 1)
                Yikes(-EIO);

            char localMd5[2 * MD5_DIGEST_LENGTH + 1];
            sprintf(localMd5,
                    "%02x%02x%02x%02x%02x%02x%02x%02x"
                    "%02x%02x%02x%02x%02x%02x%02x%02x",
                    md[0], md[1], md[2], md[3],
                    md[4], md[5], md[6], md[7],
                    md[8], md[9], md[10], md[11],
                    md[12], md[13], md[14], md[15]);

            string remoteMd5(trim(responseHeaders["ETag"], "\""));

            // md5 match?
            if (string(localMd5) != remoteMd5) {
                // no! prepare to download
                if (close(fd) == -1)
                    Yikes(-errno);
                fd = -1;
            }
        }
    }

    // need to download?
    if (fd == -1) {
        // yes!

        if (use_cache.size() > 0) {
            // only download files, not folders
            // TODO: handle missing metadata more gracefully
            mode_t mode = strtoul(responseHeaders["x-amz-meta-mode"].c_str(),
                    (char **) NULL, 10);
            if (S_ISREG(mode)) {
                // assume creating dirs in the cache succeeds ...
                mkdirp(resolved_path + mydirname(path), 0777);
                fd = open(cache_path.c_str(), O_CREAT|O_RDWR|O_TRUNC, mode);
            } else {
                // its a folder; do *not* create anything in local cache...
                // (###TODO do this in a better way)
                fd = fileno(tmpfile());
            }
        } else {
            fd = fileno(tmpfile());
        }

        if (fd == -1)
            Yikes(-errno);

        auto_curl curl;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

        int dupfd = dup(fd);
        FILE *f = fdopen(dupfd, "w+");
        if (!f)
            Yikes(-errno);
        curl_easy_setopt(curl, CURLOPT_FILE, f);

        auto_curl_slist headers;
        string date = get_date();
        headers.append("Date: "+date);
        headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
                calc_signature("GET", "", date, headers.get(), resource));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

#ifdef DEBUG
        syslog(LOG_INFO, "downloading[%s]", path);
#endif

        VERIFY(my_curl_easy_perform(curl.get(), f));

        fflush(f);

        // close the FILE * and the dup fd; the original fd is not closed
        fclose(f);

        if (fd == -1)
            Yikes(-errno);
    }

    return fd;
}

/**
 * create or update s3 meta
 * @return fuse return code
 */
int put_headers(const char *path, headers_t head) {
#ifdef DEBUG
    syslog(LOG_INFO, "put_headers[%s]", path);
#endif

    string resource = urlEncode("/" + bucket + path);
    string url = host + resource;

    auto_curl curl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

    string responseText;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

    curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length

    string ContentType = head["Content-Type"];

    auto_curl_slist headers;
    string date = get_date();
    headers.append("Date: " + date);

    head["x-amz-acl"] =
        getAcl(strtoul(head["x-amz-meta-mode"].c_str(), NULL, 10));

    for (headers_t::iterator iter = head.begin(); iter != head.end(); ++iter) {
        string key = (*iter).first;
        string value = (*iter).second;
        if (key == "Content-Type")
            headers.append(key + ":" + value);
        if (key.substr(0, 9) == "x-amz-acl")
            headers.append(key + ":" + value);
        if (key.substr(0, 10) == "x-amz-meta")
            headers.append(key + ":" + value);
        if (key == "x-amz-copy-source")
            headers.append(key + ":" + value);
    }

    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
            calc_signature("PUT", ContentType, date, headers.get(), resource));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

    //###rewind(f);

#ifdef DEBUG
    syslog(LOG_INFO, "copying[%s] -> [%s]",
            head["x-amz-copy-source"].c_str(), path);
#endif

    VERIFY(my_curl_easy_perform(curl.get()));

    return 0;
}

int s3fs_getattr(const char *path, struct stat *stbuf) {
#ifdef DEBUG
    syslog(LOG_INFO, "getattr[%s]", path);
#endif

    try {
        Fileinfo info = get_fileinfo(path);
        info.toStat(stbuf);
        return 0;
    } catch (int e) {
        if (e == -ENOENT) {
#ifdef DEBUG
            syslog(LOG_INFO, "getattr[%s]: File not found", path);
#endif
        } else {
            syslog(LOG_INFO, "getattr[%s]: %s", path, strerror(e));
        }
        return e;
    }
}

int s3fs_readlink(const char *path, char *buf, size_t size) {
#ifdef DEBUG
    syslog(LOG_INFO, "readlink[%s]", path);
#endif

    if (size > 0) {
        size--; // reserve nil terminator

        auto_fd fd(get_local_fd(path));

        struct stat st;
        if (fstat(fd.get(), &st) == -1)
            Yikes(-errno);

        if ((size_t) st.st_size < size)
            size = st.st_size;

        if (pread(fd.get(), buf, size, 0) == -1)
            Yikes(-errno);

        buf[size] = 0;
    }

    return 0;
}

// create a new file/directory
int generic_put(const char *path, mode_t mode, int fd) {
    string resource = urlEncode("/" + bucket + path);
    string url = host + resource;

    // start with generic stats for a new, empty file
    Fileinfo info(path, getuid(), getgid(), mode, time(NULL), 0, MD5_EMPTY);

    // does this file have existing stats?
    try {
        info = get_fileinfo(path);
        info.mode = mode;
    } catch (int e) {
        // if it does not exist, that is okay. other errors are a problem
        if (e != -ENOENT)
            return e;
    }

    // does this file have contents to be transmitted?
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) < 0)
            return -errno;

        // for now just grab the size
        info.size = st.st_size;
    }

    auto_curl curl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT

    // set it up to upload the file contents
    string responseText;
    FILE *f = NULL;
    if (fd < 0 || info.size == 0) {
        // easy case--no contents
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0
    } else {
        // set it up to upload from a file descriptor
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                static_cast<curl_off_t>(info.size)); // Content-Length
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

        // dup the file descriptor and make a FILE * out of it
        int dupfd = dup(fd);
        if (dupfd < 0)
            Yikes(-errno);

        f = fdopen(dupfd, "rb");
        if (!f) {
            close(dupfd);
            Yikes(-errno);
        }
        curl_easy_setopt(curl, CURLOPT_INFILE, f);
    }

    string contentType(DEFAULT_MIME_TYPE);
    if (mode & S_IFDIR)
        contentType = "application/x-directory";
    else if (mode & S_IFREG)
        contentType = lookupMimeType(path);

    auto_curl_slist headers;
    string date = get_date();
    headers.append("Date: " + date);
    headers.append("Content-Type: " + contentType);
    // x-amz headers: (a) alphabetical order and (b) no spaces after colon
    headers.append("x-amz-acl:" + getAcl(info.mode));
    headers.append("x-amz-meta-gid:" + str(info.gid));
    headers.append("x-amz-meta-mode:" + str(info.mode));
    headers.append("x-amz-meta-mtime:" + str(info.mtime));
    headers.append("x-amz-meta-uid:" + str(info.uid));
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
            calc_signature("PUT", contentType, date, headers.get(), resource));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

#ifdef DEBUG
    if (fd >= 0 && info.size > 0) {
        syslog(LOG_INFO, "uploading[%s] size[%llu]", path,
                (unsigned long long) info.size);
    }
#endif

    attrcache->del(path);

    VERIFY(my_curl_easy_perform(curl.get()));

    // close the dup fd and FILE *; leave the original fd alone
    if (f)
        fclose(f);

    attrcache->set(info);

    return 0;
}

int s3fs_mknod(const char *path, mode_t mode, dev_t rdev) {
#ifdef DEBUG
    syslog(LOG_INFO, "mknod[%s] mode[0%o]", path, mode);
#endif

    // see man 2 mknod
    // If pathname already exists, or is a symbolic link,
    // this call fails with an EEXIST error.

    return generic_put(path, mode | S_IFREG);
}

int s3fs_mkdir(const char *path, mode_t mode) {
#ifdef DEBUG
    syslog(LOG_INFO, "mkdir[%s] mode[0%o]", path, mode);
#endif

    return generic_put(path, mode | S_IFDIR);
}

int generic_remove(const char *path) {
    attrcache->del(path);

    string resource = urlEncode("/" + bucket + path);
    string url = host + resource;

    auto_curl curl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    auto_curl_slist headers;
    string date = get_date();
    headers.append("Date: " + date);
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
            calc_signature("DELETE", "", date, headers.get(), resource));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

    VERIFY(my_curl_easy_perform(curl.get()));

    return 0;
}

int s3fs_unlink(const char *path) {
#ifdef DEBUG
    syslog(LOG_INFO, "unlink[%s]", path);
#endif

    return generic_remove(path);
}

int s3fs_rmdir(const char *path) {
#ifdef DEBUG
    syslog(LOG_INFO, "rmdir[%s]", path);
#endif

    return generic_remove(path);
}

int s3fs_symlink(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "symlink[%s] -> [%s]", from, to);
#endif

    // put the link target into a file
    FILE *fp = tmpfile();
    int fd = fileno(fp);

    if (pwrite(fd, from, strlen(from), 0) == -1) {
        fclose(fp);
        Yikes(-errno);
    }

    int result = generic_put(to, S_IFLNK, fd);

    fclose(fp);

    return result;
}

int s3fs_rename(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "rename[%s] -> [%s]", from, to);
#endif

    try {
        Fileinfo info = get_fileinfo(from);

        // no renaming directories (yet)
        if (info.mode & S_IFDIR)
            return -ENOTSUP;

        info.updateHeaders(to);

        return s3fs_unlink(from);
    } catch (int e) {
        return e;
    }
}

int s3fs_link(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "link[%s] -> [%s]", from, to);
#endif

    try {
        Fileinfo info = get_fileinfo(from);

        // no linking directories
        if (info.mode & S_IFDIR)
            return -ENOTSUP;

        info.updateHeaders(to);

        return 0;
    } catch (int e) {
        return e;
    }
}

int s3fs_chmod(const char *path, mode_t mode) {
#ifdef DEBUG
    syslog(LOG_INFO, "chmod[%s] mode[0%o]", path, mode);
#endif

    try {
        Fileinfo info = get_fileinfo(path);

        // make sure we have a file type
        if (!(mode & S_IFMT))
            mode |= (info.mode & S_IFMT);

        info.mode = mode;

        info.updateHeaders();

        return 0;
    } catch (int e) {
        return e;
    }
}

int s3fs_chown(const char *path, uid_t uid, gid_t gid) {
#ifdef DEBUG
    syslog(LOG_INFO, "chown[%s] uid[%d] gid[%d]", path, uid, gid);
#endif

    try {
        Fileinfo info = get_fileinfo(path);

        // uid or gid < 0 indicates no change
        if ((int) uid >= 0)
            info.uid = uid;
        if ((int) gid >= 0)
            info.gid = gid;

        info.updateHeaders();

        return 0;
    } catch (int e) {
        return e;
    }
}

int s3fs_truncate(const char *path, off_t size) {
#ifdef DEBUG
    syslog(LOG_INFO, "truncate[%s] size[%llu]", path, size);
#endif

    if (size != 0)
        return -ENOTSUP;

    // this is just like creating a new file of length zero,
    // but keeping the old attributes
    try {
        Fileinfo info = get_fileinfo(path);
        return generic_put(path, info.mode);
    } catch (int e) {
        return e;
    }
}

int s3fs_open(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "open[%s] flags[0%o]", path, fi->flags);
#endif

    //###TODO check fi->fh here...
    fi->fh = get_local_fd(path);

    // remember flags and headers...
    auto_lock lock(s3fs_descriptors_lock);

    s3fs_descriptors[fi->fh] = fi->flags;

    return 0;
}

int s3fs_read(const char *path, char *buf,
        size_t size, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "read[%s] size[%u] offset[%llu]", path, size, offset);
#endif

    int res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        Yikes(-errno);
    return res;
}

int s3fs_write(const char *path, const char *buf,
        size_t size, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "write[%s] size[%u] offset[%llu]", path, size, offset);
#endif

    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        Yikes(-errno);
    return res;
}

int s3fs_statfs(const char *path, struct statvfs *stbuf) {
#ifdef DEBUG
    syslog(LOG_INFO, "statfs[%s]", path);
#endif

    // 256T
    stbuf->f_bsize = 0X1000000;
    stbuf->f_blocks = 0X1000000;
    stbuf->f_bfree = 0x1000000;
    stbuf->f_bavail = 0x1000000;
    return 0;
}

int get_flags(int fd) {
    auto_lock lock(s3fs_descriptors_lock);
    return s3fs_descriptors[fd];
}

int s3fs_flush(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "flush[%s]", path);
#endif

    int fd = fi->fh;

    // fi->flags is not available here
    int flags = get_flags(fd);

    // if it was opened with write permission, assume it has changed
    if ((flags & O_RDWR) || (flags & O_WRONLY)) {
        try {
            Fileinfo info = get_fileinfo(path);
            return generic_put(path, info.mode, fd);
        } catch (int e) {
            return e;
        }
    }

    // nothing to do
    return 0;
}

int s3fs_release(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "release[%s]", path);
#endif

    int fd = fi->fh;
    if (close(fd) == -1)
        Yikes(-errno);
    return 0;
}

time_t my_timegm(struct tm *tm) {
    time_t ret;
    char *tz;

    tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(tm);
    if (tz)
        setenv("TZ", tz, 1);
    else
        unsetenv("TZ");
    tzset();
    return ret;
}

int s3fs_readdir(const char *path, void *buf,
        fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "readdir[%s] offset[%llu]", path, offset);
#endif

    filler(buf, ".", 0, 0);
    filler(buf, "..", 0, 0);

    string NextMarker;
    string IsTruncated("true");

    while (IsTruncated == "true") {
        string responseText;
        string resource = urlEncode("/" + bucket); // this is what gets signed
        string query = "delimiter=/&prefix=";

        if (strcmp(path, "/") != 0)
            query += urlEncode(string(path).substr(1) + "/");

        if (NextMarker.size() > 0)
            query += "&marker=" + urlEncode(NextMarker);

        query += "&max-keys=";
        query += MAX_KEYS_PER_DIR_REQUEST;

        string url = host + resource + "?" + query;

        {
            auto_curl curl;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

            auto_curl_slist headers;
            string date = get_date();
            headers.append("Date: " + date);
            headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
                    calc_signature("GET", "", date, headers.get(), resource));

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

            VERIFY(my_curl_easy_perform(curl.get()));
        }

        xmlDocPtr doc = xmlReadMemory(responseText.c_str(),
                responseText.size(), "", NULL, 0);
        if (!doc || !doc->children) {
            xmlFreeDoc(doc);
            continue;
        }
        for (xmlNodePtr cur_node = doc->children->children; cur_node != NULL;
                cur_node = cur_node->next)
        {
            string cur_node_name(reinterpret_cast<const char *>(
                        cur_node->name));
            if (cur_node_name == "IsTruncated")
                IsTruncated = reinterpret_cast<const char *>(
                        cur_node->children->content);
            if (cur_node_name == "NextMarker")
                NextMarker = reinterpret_cast<const char *>(
                        cur_node->children->content);
            if (cur_node_name != "Contents" || cur_node->children == NULL)
                continue;

            string Key;
            for (xmlNodePtr sub_node = cur_node->children; sub_node != NULL;
                    sub_node = sub_node->next)
            {
                if (    sub_node->type != XML_ELEMENT_NODE ||
                        !sub_node->children ||
                        sub_node->children->type != XML_TEXT_NODE)
                {
                    continue;
                }

                string elementName =
                    reinterpret_cast<const char *>(sub_node->name);

                if (elementName == "Key")
                    Key = reinterpret_cast<const char *>(
                            sub_node->children->content);
            }
            if (Key.size() > 0) {
                if (filler(buf, mybasename(Key).c_str(), 0, 0))
                    break;
            }
        }
        xmlFreeDoc(doc);
    } // IsTruncated

    return 0;
}

/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&mutex_buf[n]);
    } else {
        pthread_mutex_unlock(&mutex_buf[n]);
    }
}

/**
 * OpenSSL uniq id function.
 *
 * @return    thread id
 */
unsigned long id_function(void) {
    return ((unsigned long) pthread_self());
}

void *s3fs_init(struct fuse_conn_info *conn) {
    syslog(LOG_INFO, "init[%s]", bucket.c_str());

    // openssl
    mutex_buf = static_cast<pthread_mutex_t *>(
            malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t)));
    for (int i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&mutex_buf[i], NULL);
    CRYPTO_set_locking_callback(locking_function);
    CRYPTO_set_id_callback(id_function);
    curl_global_init(CURL_GLOBAL_ALL);
    pthread_mutex_init(&curl_handles_lock, NULL);
    pthread_mutex_init(&s3fs_descriptors_lock, NULL);

    string line;
    ifstream passwd("/etc/mime.types");
    while (getline(passwd, line)) {
        if (line[0] == '#')
            continue;
        stringstream tmp(line);
        string mimeType;
        tmp >> mimeType;
        while (tmp) {
            string ext;
            tmp >> ext;
            if (ext.size() == 0)
                continue;
            mimeTypes[ext] = mimeType;
        }
    }
    return 0;
}

void s3fs_destroy(void*) {
    syslog(LOG_INFO, "destroy[%s]", bucket.c_str());

    // openssl
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;
    curl_global_cleanup();
    pthread_mutex_destroy(&curl_handles_lock);
    pthread_mutex_destroy(&s3fs_descriptors_lock);
}

int s3fs_access(const char *path, int mask) {
#ifdef DEBUG
    syslog(LOG_INFO, "access[%s] mask[0%o]", path, mask);
#endif

    return 0;
}

// aka touch
int s3fs_utimens(const char *path, const struct timespec ts[2]) {
#ifdef DEBUG
    syslog(LOG_INFO, "utimens[%s] mtime[%ld]", path, ts[1].tv_sec);
#endif

    try {
        Fileinfo info = get_fileinfo(path);

        info.mtime = ts[1].tv_sec;

        info.updateHeaders();

        return 0;
    } catch (int e) {
        return e;
    }
}

int my_fuse_opt_proc(void *data, const char *arg,
        int key, struct fuse_args *outargs)
{
    if (key == FUSE_OPT_KEY_NONOPT) {
        if (bucket.size() == 0) {
            bucket = arg;
            return 0;
        } else {
            struct stat buf;
            // its the mountpoint... what is its mode?
            if (stat(arg, &buf) != -1) {
                root_mode = buf.st_mode;
            }
        }
    }
    if (key == FUSE_OPT_KEY_OPT) {
        if (strstr(arg, "accessKeyId=") != 0) {
            AWSAccessKeyId = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "secretAccessKey=") != 0) {
            AWSSecretAccessKey = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "default_acl=") != 0) {
            default_acl = strchr(arg, '=') + 1;
            return 0;
        }
        // ### TODO: prefix
        if (strstr(arg, "retries=") != 0) {
            retries = atoi(strchr(arg, '=') + 1);
            return 0;
        }
        if (strstr(arg, "use_cache=") != 0) {
            use_cache = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "connect_timeout=") != 0) {
            connect_timeout = strtol(strchr(arg, '=') + 1, 0, 10);
            return 0;
        }
        if (strstr(arg, "readwrite_timeout=") != 0) {
            readwrite_timeout = strtoul(strchr(arg, '=') + 1, 0, 10);
            return 0;
        }
        if (strstr(arg, "url=") != 0) {
            host = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "attr_cache=") != 0) {
            attr_cache = strchr(arg, '=') + 1;
            return 0;
        }
    }
    return 1;
}

struct fuse_operations s3fs_oper;

int main(int argc, char *argv[]) {
    bzero(&s3fs_oper, sizeof(s3fs_oper));

    struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc);

    if (bucket.size() == 0) {
        cout << argv[0] << ": " << "missing bucket" << endl;
        exit(1);
    }

    if (AWSSecretAccessKey.size() == 0) {
        string line;
        ifstream passwd("/etc/passwd-s3fs");
        while (getline(passwd, line)) {
            if (line[0]=='#')
                continue;
            size_t pos = line.find(':');
            if (pos != string::npos) {
                // is accessKeyId missing?
                if (AWSAccessKeyId.size() == 0)
                    AWSAccessKeyId = line.substr(0, pos);
                // is secretAccessKey missing?
                if (AWSSecretAccessKey.size() == 0) {
                    if (line.substr(0, pos) == AWSAccessKeyId)
                        AWSSecretAccessKey = line.substr(pos + 1, string::npos);
                }
            }
        }
    }

    if (AWSAccessKeyId.size() == 0) {
        cout << argv[0] << ": " << "missing accessKeyId.. see "
            "/etc/passwd-s3fs or use, e.g., -o accessKeyId=aaa" << endl;
        exit(1);
    }
    if (AWSSecretAccessKey.size() == 0) {
        cout << argv[0] << ": " << "missing secretAccessKey... see "
            "/etc/passwd-s3fs or use, e.g., -o secretAccessKey=bbb" << endl;
        exit(1);
    }

    s3fs_oper.getattr = s3fs_getattr;
    s3fs_oper.readlink = s3fs_readlink;
    s3fs_oper.mknod = s3fs_mknod;
    s3fs_oper.mkdir = s3fs_mkdir;
    s3fs_oper.unlink = s3fs_unlink;
    s3fs_oper.rmdir = s3fs_rmdir;
    s3fs_oper.symlink = s3fs_symlink;
    s3fs_oper.rename = s3fs_rename;
    s3fs_oper.link = s3fs_link;
    s3fs_oper.chmod = s3fs_chmod;
    s3fs_oper.chown = s3fs_chown;
    s3fs_oper.truncate = s3fs_truncate;
    s3fs_oper.open = s3fs_open;
    s3fs_oper.read = s3fs_read;
    s3fs_oper.write = s3fs_write;
    s3fs_oper.statfs = s3fs_statfs;
    s3fs_oper.flush = s3fs_flush;
    s3fs_oper.release = s3fs_release;
    s3fs_oper.readdir = s3fs_readdir;
    s3fs_oper.init = s3fs_init;
    s3fs_oper.destroy = s3fs_destroy;
    s3fs_oper.access = s3fs_access;
    s3fs_oper.utimens = s3fs_utimens;

    attrcache = new Attrcache(bucket.c_str());

    int status =
        fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);

    delete attrcache;
    return status;
}
