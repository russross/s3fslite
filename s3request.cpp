#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "s3fs.h"
#include "fileinfo.h"
#include "s3request.h"

typedef std::map<std::string, std::string> headers_t;
static const EVP_MD *evp_md = EVP_sha1();

template<typename T>
std::string str(T value) {
    std::stringstream tmp;
    tmp << value;
    return tmp.str();
}

/**
 * @param s e.g., "index.html"
 * @return e.g., "text/html"
 */
std::string lookupMimeType(std::string path) {
    std::string result(DEFAULT_MIME_TYPE);
    std::string ext(path);
    std::string::size_type pos = ext.find_last_of('.');
    if (pos != std::string::npos) {
        ext = ext.substr(1 + pos, std::string::npos);
    }
    mimes_t::const_iterator iter = mimeTypes.find(ext);
    if (iter != mimeTypes.end())
        result = (*iter).second;
    return result;
}

std::string getAcl(mode_t mode) {
    if (default_acl != "")
        return default_acl;
    if (mode & S_IROTH)
        return public_acl;
    return private_acl;
}

// gather headers as a response is parsed
static size_t header_callback(void *data, size_t blockSize, size_t numBlocks,
        void *userPtr)
{
    headers_t *headers = static_cast<headers_t *>(userPtr);
    std::string header(static_cast<char *>(data), blockSize * numBlocks);
    std::string key;
    std::stringstream ss(header);
    if (std::getline(ss, key, ':')) {
        std::string value;
        std::getline(ss, value);
        (*headers)[key] = trim_spaces(value);
    }
    return blockSize * numBlocks;
}

// libcurl callback
size_t readCallback(void *data, size_t blockSize, size_t numBlocks,
        void *userPtr)
{
    std::string *userString = static_cast<std::string *>(userPtr);
    size_t count = std::min((*userString).size(), blockSize * numBlocks);
    memcpy(data, (*userString).data(), count);
    (*userString).erase(0, count);
    return count;
}

// libcurl callback
size_t writeCallback(void* data, size_t blockSize, size_t numBlocks,
        void *userPtr)
{
    std::string *userString = static_cast<std::string *>(userPtr);
    (*userString).append(static_cast<const char *>(data),
            blockSize * numBlocks);
    return blockSize * numBlocks;
}

// watch for timeouts during transfer
static int progress(void *clientp, double dltotal,
        double dlnow, double ultotal, double ulnow)
{
    S3request *req = static_cast<S3request *>(clientp);
    time_t now = time(0);

    // any progress?
    if (dlnow != req->dlnow || ulnow != req->ulnow) {
        // yes!
        req->last_time = now;
        req->dlnow = dlnow;
        req->ulnow = ulnow;
    } else if (now - req->last_time > readwrite_timeout) {
        // timeout?
        return CURLE_ABORTED_BY_CALLBACK;
    }

    return 0;
}

/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */

static std::string hexAlphabet = "0123456789ABCDEF";

static std::string urlEncode(const std::string &s) {
    std::string result;
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

/**
 * Returns the current date
 * in a format suitable for a HTTP request header.
 */
std::string get_date() {
    char buf[100];
    time_t t = time(NULL);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
    return buf;
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

// note: returns a buffer that must be delete[]ed
unsigned char *get_md5(int fd) {
    MD5_CTX c;
    if (MD5_Init(&c) != 1)
        throw -EIO;

    // start reading the file from the beginning
    lseek(fd, 0, SEEK_SET);

    int count;
    char buf[4096];
    while ((count = read(fd, buf, sizeof(buf))) > 0) {
        if (MD5_Update(&c, buf, count) != 1)
            throw -EIO;
    }

    unsigned char *md = new unsigned char[MD5_DIGEST_LENGTH];
    if (MD5_Final(md, &c) != 1) {
        delete[] md;
        throw -EIO;
    }

    return md;
}

std::string md5_to_string(unsigned char *md) {
    char localMd5[2 * MD5_DIGEST_LENGTH + 1];
    sprintf(localMd5,
            "%02x%02x%02x%02x%02x%02x%02x%02x"
            "%02x%02x%02x%02x%02x%02x%02x%02x",
            md[0], md[1], md[2], md[3],
            md[4], md[5], md[6], md[7],
            md[8], md[9], md[10], md[11],
            md[12], md[13], md[14], md[15]);

    std::string sum(localMd5);
    return sum;
}


std::string base64_encode(unsigned char *md, unsigned md_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md, md_len);

    // (void) is to silence a warning
    (void) BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result;
    result.resize(bptr->length - 1);
    memcpy(&result[0], bptr->data, bptr->length-1);

    BIO_free_all(b64);

    return result;
}

S3request::S3request(std::string path, std::string query) {
    curl = curl_easy_init();

    // set up flags
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
    curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress);
    curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, this);

    std::string url;

    // readdir requests need special treatment
    if (query == "") {
        resource = urlEncode("/" + bucket + path);
        url = host + resource;
    } else {
        resource = urlEncode("/" + bucket);
        url = host + resource + "?" + query;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

    // set up progress tracking
    last_time = time(0);
    dlnow = -1;
    ulnow = -1;

    // set up headers
    headers = NULL;

    // set up open file handle
    fp = NULL;
}

S3request::~S3request() {
    if (curl) {
        curl_easy_cleanup(curl);
        curl = NULL;
    }
    if (headers) {
        curl_slist_free_all(headers);
        headers = NULL;
    }
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
}

void S3request::add_header(const std::string &s) {
    headers = curl_slist_append(headers, s.c_str());
}

void S3request::sign_request(std::string method, std::string content_md5,
        std::string content_type, std::string date)
{
    std::string msg;
    msg += method + "\n";
    msg += content_md5 + "\n";
    msg += content_type + "\n";
    msg += date + "\n";
    int count = 0;

    curl_slist *elt = headers;
    while (elt) {
        if (!strncmp(elt->data, "x-amz", 5)) {
            count++;
            msg += elt->data;
            msg += '\n';
        }
        elt = elt->next;
    }
    msg += resource;

    const void *key = AWSSecretAccessKey.data();
    int key_len = AWSSecretAccessKey.size();
    const unsigned char *d =
        reinterpret_cast<const unsigned char *>(msg.data());
    int n = msg.size();
    unsigned int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];

    HMAC(evp_md, key, key_len, d, n, md, &md_len);

    std::string signature = base64_encode(md, md_len);
    add_header("Authorization: AWS " + AWSAccessKeyId + ":" + signature);
}

/**
 * @return fuse return code
 */
void S3request::execute() {
    // bind the headers to the request
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // 1 attempt + retries...
    int t = 1 + retries;
    while (t-- > 0) {
        CURLcode curlCode = curl_easy_perform(curl);
        if (curlCode == 0) {
            return;
        } else if (curlCode == CURLE_OPERATION_TIMEDOUT) {
#ifdef DEBUG_WIRE
            syslog(LOG_INFO, "curl timeout");
#endif
        } else if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
            long responseCode;
            if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
                        &responseCode) != 0)
            {
                throw -EIO;
            }
            if (responseCode == 404)
                throw -ENOENT;

            if (responseCode == 403)
                throw -EACCES;

            syslog(LOG_ERR, "curl unexpected error code [%ld]", responseCode);

            if (responseCode < 500)
                throw -EIO;
        } else {
            syslog(LOG_ERR, "curl error[%s]", curl_easy_strerror(curlCode));;
        }
#ifdef DEBUG_WIRE
        syslog(LOG_INFO, "curl retrying...");
#endif
    }
    syslog(LOG_ERR, "curl giving up after %d tries", retries + 1);
    throw -EIO;
}

Fileinfo *S3request::get_fileinfo(std::string path) {
#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "S3request::get_fileinfo[%s]", path.c_str());
#endif

    std::string date = get_date();

    S3request req(path);
    headers_t response;

    // store the response headers in a map
    curl_easy_setopt(req.curl, CURLOPT_HEADERDATA, &response);
    curl_easy_setopt(req.curl, CURLOPT_HEADERFUNCTION, header_callback);

    // CURLOPT_NOBODY => HEAD
    curl_easy_setopt(req.curl, CURLOPT_NOBODY, true);

    // CURLOPT_FILETIME == retrieve Last-Modified field
    curl_easy_setopt(req.curl, CURLOPT_FILETIME, true);

    // set all the headers
    req.add_header("Date: " + date);
    req.sign_request("HEAD", "", "", date);
    req.execute();

    // fill in info based on header results
    unsigned mtime = num(response["x-amz-meta-mtime"]);
    if (mtime == 0) {
        // no mtime header? Parse the Last-Modified header instead
        // Last-Modified: Fri, 25 Sep 2009 22:24:38 GMT
        struct tm tm;
        strptime(response["Last-Modified"].c_str(),
                "%a, %d %b %Y %H:%M:%S GMT", &tm);
        mtime = mktime(&tm);
    }

    mode_t mode = num(response["x-amz-meta-mode"]);
    if (!(mode & S_IFMT)) {
        // missing file type: try to at least figure out if it is a directory
        if (response["Content-Type"] == DIRECTORY_MIME_TYPE)
            mode |= S_IFDIR;
        else
            mode |= S_IFREG;
    }

    size_t size = longnum(response["Content-Length"]);
    unsigned uid = num(response["x-amz-meta-uid"]);
    unsigned gid = num(response["x-amz-meta-gid"]);

    return new Fileinfo(path, uid, gid, mode, mtime, size);
}

// path is the source file to copy
// info contains the details to set, and the target path
// if path and info->path are the same, the file is updated in place
void S3request::set_fileinfo(std::string path, Fileinfo *info) {
#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "S3request::set_fileinfo[%s]", path.c_str());
#endif

    std::string content_type(DEFAULT_MIME_TYPE);
    if (info->mode & S_IFDIR)
        content_type = DIRECTORY_MIME_TYPE;
    else if (info->mode & S_IFREG)
        content_type = lookupMimeType(info->path);
    std::string date = get_date();

    S3request req(info->path);
    std::string response;

    // store the entire response in a string
    curl_easy_setopt(req.curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(req.curl, CURLOPT_WRITEFUNCTION, writeCallback);

    // CURLOPT_UPLOAD => PUT
    curl_easy_setopt(req.curl, CURLOPT_UPLOAD, true);

    // CURLOPT_INFILESIZE == Content-Length
    curl_easy_setopt(req.curl, CURLOPT_INFILESIZE, 0);

    // set all the headers
    req.add_header("Date: " + date);
    req.add_header("Content-Type:" + content_type);
    req.add_header("x-amz-acl:" + getAcl(info->mode));
    req.add_header("x-amz-copy-source:" + urlEncode("/" + bucket + path));
    req.add_header("x-amz-meta-gid:" + str(info->gid));
    req.add_header("x-amz-meta-mode:" + str(info->mode));
    req.add_header("x-amz-meta-mtime:" + str(info->mtime));
    req.add_header("x-amz-meta-uid:" + str(info->uid));
    req.add_header("x-amz-metadata-directive:REPLACE");
    req.sign_request("PUT", "", content_type, date);

#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "copying[%s] -> [%s]", path.c_str(), info->path.c_str());
#endif

    req.execute();
}

int S3request::get_file(std::string path, Fileinfo *info) {
#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "S3request::get_file[%s]", path.c_str());
#endif

    std::string date = get_date();

    // create a temporary local file
    int fd = create_tempfile();

    // zero-length files are easy to download
    if (info->size == 0)
        return fd;

    S3request req(path);
    headers_t response;

    // store the response headers in a map
    curl_easy_setopt(req.curl, CURLOPT_HEADERDATA, &response);
    curl_easy_setopt(req.curl, CURLOPT_HEADERFUNCTION, header_callback);

    int dupfd = dup(fd);
    if (dupfd < 0) {
        int err = -errno;
        close(fd);
        throw err;
    }
    req.fp = fdopen(dupfd, "w+");
    if (!req.fp) {
        int err = -errno;
        close(fd);
        close(dupfd);
        throw err;
    }

    // store the response in the temporary file
    curl_easy_setopt(req.curl, CURLOPT_FILE, req.fp);

    // set all the headers
    req.add_header("Date: " + date);
    req.sign_request("GET", "", "", date);

    req.execute();

    // check its md5 sum
    std::string etag = trim_quotes(response["ETag"]);
    fflush(req.fp);
    unsigned char *md = get_md5(fd);
    std::string md5sum = md5_to_string(md);
    delete[] md;

    if (md5sum != etag) {
        // file corrupted during download
        syslog(LOG_ERR, "S3request::get_file md5: expected[%s] received[%s]",
                etag.c_str(), md5sum.c_str());
        close(fd);
        throw -EIO;
    }

    // the FILE * and dupfd will be closed when req is deleted

    return fd;
}

void S3request::put_file(Fileinfo *info, int fd) {
#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "S3request::put_file[%s]", info->path.c_str());
#endif

    std::string content_type(DEFAULT_MIME_TYPE);
    if (info->mode & S_IFDIR)
        content_type = DIRECTORY_MIME_TYPE;
    else if (info->mode & S_IFREG)
        content_type = lookupMimeType(info->path);
    std::string date = get_date();

    S3request req(info->path);
    std::string response;

    // store the entire response in a string
    curl_easy_setopt(req.curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(req.curl, CURLOPT_WRITEFUNCTION, writeCallback);

    // CURLOPT_UPLOAD => PUT
    curl_easy_setopt(req.curl, CURLOPT_UPLOAD, true);

    // set it up to upload the file contents
    std::string md5sum;
    if (fd < 0 || info->size == 0) {
        // easy case--no contents
        // CURLOPT_INFILESIZE == Content-Length
        curl_easy_setopt(req.curl, CURLOPT_INFILESIZE, 0);
    } else {
        // set it up to upload from a file descriptor
        unsigned char *md = get_md5(fd);
        md5sum = base64_encode(md, MD5_DIGEST_LENGTH);
        delete[] md;

        // CURLOPT_INFILESIZE_LARGE == Content-Length
        curl_easy_setopt(req.curl, CURLOPT_INFILESIZE_LARGE,
                static_cast<curl_off_t>(info->size));

        // dup the file descriptor and make a FILE * out of it
        lseek(fd, 0, SEEK_SET);
        int dupfd = dup(fd);
        if (dupfd < 0)
            throw -errno;

        req.fp = fdopen(dupfd, "rb");
        if (!req.fp) {
            close(dupfd);
            throw -errno;
        }

        // read the contents from an open FILE *
        curl_easy_setopt(req.curl, CURLOPT_INFILE, req.fp);
    }

    // set all the headers
    // x-amz headers: (a) alphabetical order and (b) no spaces after colon
    req.add_header("Date: " + date);
    if (md5sum != "") req.add_header("Content-MD5: " + md5sum);
    req.add_header("Content-Type: " + content_type);
    req.add_header("x-amz-acl:" + getAcl(info->mode));
    req.add_header("x-amz-meta-gid:" + str(info->gid));
    req.add_header("x-amz-meta-mode:" + str(info->mode));
    req.add_header("x-amz-meta-mtime:" + str(info->mtime));
    req.add_header("x-amz-meta-uid:" + str(info->uid));
    req.sign_request("PUT", md5sum, content_type, date);

#ifdef DEBUG_WIRE
    if (fd >= 0 && info->size > 0) {
        syslog(LOG_INFO, "uploading[%s] size[%llu]", info->path.c_str(),
                (unsigned long long) info->size);
    }
#endif

    req.execute();
}

void S3request::remove(std::string path) {
#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "S3request::remove[%s]", path.c_str());
#endif

    std::string date = get_date();

    S3request req(path);
    std::string response;

    // store the entire response in a string
    curl_easy_setopt(req.curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(req.curl, CURLOPT_WRITEFUNCTION, writeCallback);

    // DELETE request
    curl_easy_setopt(req.curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    // set all the headers
    req.add_header("Date: " + date);
    req.sign_request("DELETE", "", "", date);

    req.execute();
}

// returns true if there are more entries to come
bool S3request::get_directory(std::string path, std::string &marker,
        stringlist &result, int max_entries, bool includeall)
{
#ifdef DEBUG_WIRE
    syslog(LOG_INFO, "S3request::get_directory[%s] marker[%s]", path.c_str(),
            marker.c_str());
#endif

    std::string date = get_date();

    // set up the query string
    std::string prefix;

    if (path != "/")
        prefix = urlEncode(path.substr(1) + "/");

    std::string query("prefix=" + prefix);

    if (!includeall)
        query += "&delimiter=/";

    if (marker.size() > 0)
        query += "&marker=" + urlEncode(marker);

    query += "&max-keys=";
    query += str(max_entries);

    S3request req(path, query);
    std::string response;

    // store the entire response in a string
    curl_easy_setopt(req.curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(req.curl, CURLOPT_WRITEFUNCTION, writeCallback);

    // set all the headers
    req.add_header("Date: " + date);
    req.sign_request("GET", "", "", date);

    req.execute();

    bool moretocome = false;
    marker = "";

    // parse the response
    xmlDocPtr doc =
        xmlReadMemory(response.c_str(), response.size(), "", NULL, 0);

    if (!doc || !doc->children) {
        xmlFreeDoc(doc);
        return moretocome;
    }
    for (xmlNodePtr cur_node = doc->children->children; cur_node != NULL;
            cur_node = cur_node->next)
    {
        std::string cur_node_name(reinterpret_cast<const char *>(
                    cur_node->name));
        if (cur_node_name == "IsTruncated")
            moretocome = !strcmp("true", reinterpret_cast<const char *>(
                        cur_node->children->content));
        if (cur_node_name == "NextMarker")
            marker = reinterpret_cast<const char *>(
                    cur_node->children->content);
        if (cur_node_name != "Contents" || cur_node->children == NULL)
            continue;

        std::string key;
        for (xmlNodePtr sub_node = cur_node->children; sub_node != NULL;
                sub_node = sub_node->next)
        {
            if (    sub_node->type != XML_ELEMENT_NODE ||
                    !sub_node->children ||
                    sub_node->children->type != XML_TEXT_NODE)
            {
                continue;
            }

            std::string elementName =
                reinterpret_cast<const char *>(sub_node->name);

            if (elementName == "Key")
                key = reinterpret_cast<const char *>(
                        sub_node->children->content);
        }
        if (key.size() > prefix.size()) {
            result.push_back(key.substr(prefix.size(),
                        key.size() - prefix.size()));
        }
    }
    xmlFreeDoc(doc);

    return moretocome;
}
