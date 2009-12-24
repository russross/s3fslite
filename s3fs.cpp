/*
 * s3fslite - Amazon S3 file system
 *
 * Copyright 2009 Russ Ross <russ@russross.com>
 *
 * Based on s3fs
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
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
#include <time.h>
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

// project dependencies
#include "fileinfo.h"
#include "attrcache.h"
#include "s3request.h"
#include "s3fs.h"

using namespace std;

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
    private:
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

class Transaction {
    public:
        Transaction(std::string path);
        ~Transaction();

        std::string path;
        Fileinfo *info;
};

Transaction::Transaction(std::string path) {
    this->path = path;
    info = NULL;
}

Transaction::~Transaction() {
    if (info) {
        delete info;
        info = NULL;
    }
}

static std::string SPACES(" \t\r\n");
static std::string QUOTES("\"");

std::string trim_spaces(const std::string &s) {
    string::size_type start(s.find_first_not_of(SPACES));
    string::size_type end(s.find_last_not_of(SPACES));
    if (start == string::npos || end == string::npos)
        return "";
    return s.substr(start, end + 1 - start);
}

std::string trim_quotes(const std::string &s) {
    string::size_type start(s.find_first_not_of(QUOTES));
    string::size_type end(s.find_last_not_of(QUOTES));
    if (start == string::npos || end == string::npos)
        return "";
    return s.substr(start, end + 1 - start);
}
pthread_mutex_t *mutex_buf = NULL;

mimes_t mimeTypes;

// fd -> flags
map<int, int> s3fs_descriptors;
pthread_mutex_t s3fs_descriptors_lock;

Attrcache *attrcache;

int generic_put(Transaction *t, mode_t mode, bool newfile, int fd = -1);

void copy_file(Transaction *t) {
    // special case: for the root, just update the cache
    if (t->path == "/") {
        attrcache->del(t->path);
        attrcache->set(t->info);
        return;
    }

    attrcache->del(t->path);

    S3request::set_fileinfo(t->path, t->info);

    // put the new name in the cache
    attrcache->set(t->info);
}

void get_fileinfo(Transaction *t) {
    // first check the cache
    t->info = attrcache->get(t->path);
    if (t->info)
        return;

    // special case for /
    if (t->path == "/") {
        t->info = new Fileinfo(t->path, 0, 0,
                root_mode | S_IFDIR, time(NULL), 0, MD5_EMPTY);
    } else {
        t->info = S3request::get_fileinfo(t->path);
    }

    // update the cache
    // the fake "/" entry is cached, too, so that rsync can update it
    attrcache->set(t->info);
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
 * get_local_fd
 *
 * Return the fd for a local copy of the given path.
 * Open the cached copy if available, otherwise download it
 * into the cache and return the result.
 */
int get_local_fd(Transaction *t) {
    get_fileinfo(t);

    return S3request::get_file(t->path, t->info);
}

int s3fs_getattr(const char *path, struct stat *stbuf) {
#ifdef DEBUG
    syslog(LOG_INFO, "getattr[%s]", path);
#endif

    Transaction t(path);

    try {
        get_fileinfo(&t);
        t.info->toStat(stbuf);
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

    Transaction t(path);

    if (size == 0)
        return 0;

    try {
        size--; // save room for null at the end

        auto_fd fd(get_local_fd(&t));

        struct stat st;
        if (fstat(fd.get(), &st) < 0)
            Yikes(-errno);

        if ((size_t) st.st_size < size)
            size = st.st_size;

        if (pread(fd.get(), buf, size, 0) < 0)
            Yikes(-errno);

        buf[size] = 0;
    } catch (int e) {
        return e;
    }

    return 0;
}

// create a new file/directory
int generic_put(Transaction *t, mode_t mode, bool newfile, int fd) {
    // does this file have existing stats?
    if (newfile) {
        // no, start with generic stats for a new, empty file
        t->info = new Fileinfo(t->path, getuid(), getgid(), mode,
                time(NULL), 0, MD5_EMPTY);
    } else {
        // yes, get them
        try {
            get_fileinfo(t);
            t->info->mode = mode;
        } catch (int e) {
            // if it does not exist, that is okay. other errors are a problem
            if (e != -ENOENT)
                throw e;
        }
    }

    // does this file have contents to be transmitted?
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) < 0)
            return -errno;

        // grab the size from the cached file
        t->info->size = st.st_size;
    }

    attrcache->del(t->path);

    S3request::put_file(t->info, fd);

    attrcache->set(t->info);

    return 0;
}

int s3fs_mknod(const char *path, mode_t mode, dev_t rdev) {
#ifdef DEBUG
    syslog(LOG_INFO, "mknod[%s] mode[0%o]", path, mode);
#endif

    Transaction t(path);

    // see man 2 mknod
    // If pathname already exists, or is a symbolic link,
    // this call fails with an EEXIST error.

    return generic_put(&t, mode | S_IFREG, true);
}

int s3fs_mkdir(const char *path, mode_t mode) {
#ifdef DEBUG
    syslog(LOG_INFO, "mkdir[%s] mode[0%o]", path, mode);
#endif

    Transaction t(path);

    return generic_put(&t, mode | S_IFDIR, true);
}

int generic_remove(Transaction *t) {
    attrcache->del(t->path);

    string baseName = mybasename(t->path);
    string resolved_path(use_cache + "/" + bucket);
    string cache_path(resolved_path + t->path);

    // delete the cache copy if it exists
    if (use_cache.size() > 0)
        unlink(cache_path.c_str());

    S3request::remove(t->path);
    return 0;
}

int s3fs_unlink(const char *path) {
#ifdef DEBUG
    syslog(LOG_INFO, "unlink[%s]", path);
#endif

    Transaction t(path);

    return generic_remove(&t);
}

int s3fs_rmdir(const char *path) {
#ifdef DEBUG
    syslog(LOG_INFO, "rmdir[%s]", path);
#endif

    // TODO: make sure the directory is empty
    Transaction t(path);

    return generic_remove(&t);
}

int s3fs_symlink(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "symlink[%s] -> [%s]", from, to);
#endif

    Transaction t(to);

    // put the link target into a file
    FILE *fp = tmpfile();
    int fd = fileno(fp);

    if (pwrite(fd, from, strlen(from), 0) < 0) {
        fclose(fp);
        Yikes(-errno);
    }

    int result = generic_put(&t, S_IFLNK, true, fd);

    fclose(fp);

    return result;
}

int s3fs_rename(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "rename[%s] -> [%s]", from, to);
#endif

    Transaction t(from);

    try {
        get_fileinfo(&t);

        // no renaming directories (yet)
        if (t.info->mode & S_IFDIR)
            return -ENOTSUP;

        t.info->path = to;
        copy_file(&t);

        t.path = from;
        t.info->path = from;
        return generic_remove(&t);
    } catch (int e) {
        return e;
    }
}

int s3fs_link(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "link[%s] -> [%s]", from, to);
#endif

    Transaction t(from);

    try {
        get_fileinfo(&t);

        // no linking directories
        if (t.info->mode & S_IFDIR)
            return -ENOTSUP;

        t.info->path = to;
        copy_file(&t);

        return 0;
    } catch (int e) {
        return e;
    }
}

int s3fs_chmod(const char *path, mode_t mode) {
#ifdef DEBUG
    syslog(LOG_INFO, "chmod[%s] mode[0%o]", path, mode);
#endif

    Transaction t(path);

    try {
        get_fileinfo(&t);

        // make sure we have a file type
        if (!(mode & S_IFMT))
            mode |= (t.info->mode & S_IFMT);

        t.info->mode = mode;

        copy_file(&t);

        return 0;
    } catch (int e) {
        return e;
    }
}

int s3fs_chown(const char *path, uid_t uid, gid_t gid) {
#ifdef DEBUG
    syslog(LOG_INFO, "chown[%s] uid[%d] gid[%d]", path, uid, gid);
#endif

    Transaction t(path);

    try {
        get_fileinfo(&t);

        // uid or gid < 0 indicates no change
        if ((int) uid >= 0)
            t.info->uid = uid;
        if ((int) gid >= 0)
            t.info->gid = gid;

        copy_file(&t);

        return 0;
    } catch (int e) {
        return e;
    }
}

int s3fs_truncate(const char *path, off_t size) {
#ifdef DEBUG
    syslog(LOG_INFO, "truncate[%s] size[%llu]", path,
            (unsigned long long) size);
#endif

    Transaction t(path);

    // TODO: support all sizes of truncates
    if (size != 0)
        return -ENOTSUP;

    // this is just like creating a new file of length zero,
    // but keeping the old attributes
    try {
        get_fileinfo(&t);
        return generic_put(&t, t.info->mode, false);
    } catch (int e) {
        return e;
    }
}

int s3fs_open(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "open[%s] flags[0%o]", path, fi->flags);
#endif

    Transaction t(path);

    //###TODO check fi->fh here...
    try {
        fi->fh = get_local_fd(&t);

        // remember flags and headers...
        auto_lock lock(s3fs_descriptors_lock);

        s3fs_descriptors[fi->fh] = fi->flags;
    } catch (int e) {
        return e;
    }

    return 0;
}

int s3fs_read(const char *path, char *buf,
        size_t size, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "read[%s] size[%u] offset[%llu]",
            path, (unsigned) size, (unsigned long long) offset);
#endif

    //Transaction t;

    int res = pread(fi->fh, buf, size, offset);
    if (res < 0)
        Yikes(-errno);
    return res;
}

int s3fs_write(const char *path, const char *buf,
        size_t size, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "write[%s] size[%u] offset[%llu]",
            path, (unsigned) size, (unsigned long long) offset);
#endif

    //Transaction t;

    int res = pwrite(fi->fh, buf, size, offset);
    if (res < 0)
        Yikes(-errno);
    return res;
}

int s3fs_statfs(const char *path, struct statvfs *stbuf) {
#ifdef DEBUG
    syslog(LOG_INFO, "statfs[%s]", path);
#endif

    //Transaction t;

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

    Transaction t(path);

    int fd = fi->fh;

    // fi->flags is not available here
    int flags = get_flags(fd);

    // if it was opened with write permission, assume it has changed
    if ((flags & O_RDWR) || (flags & O_WRONLY)) {
        try {
            get_fileinfo(&t);
            return generic_put(&t, t.info->mode, false, fd);
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

    //Transaction t;

    int fd = fi->fh;
    if (close(fd) < 0)
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
    syslog(LOG_INFO, "readdir[%s] offset[%llu]",
            path, (unsigned long long) offset);
#endif

    //Transaction t(path);

    filler(buf, ".", 0, 0);
    filler(buf, "..", 0, 0);

    string marker;
    int moretocome = 1;

    while (moretocome) {
        stringlist entries;
        moretocome = S3request::get_directory(path, marker, entries);

        for (size_t i = 0; i < entries.size(); i++) {
            if (filler(buf, entries[i].c_str(), 0, 0)) {
                syslog(LOG_ERR, "readdir: buffer full");
                break;
            }
        }
    }

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

    Transaction t(path);

    try {
        get_fileinfo(&t);

        t.info->mtime = ts[1].tv_sec;

        copy_file(&t);

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

    attrcache = new Attrcache(bucket, attr_cache);

    int status =
        fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);

    delete attrcache;
    return status;
}
