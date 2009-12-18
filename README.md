s3fslite
========

s3fslite is a fork of s3fs, originally written by Randy Rizun. It is
a file system that stores all data in an Amazon S3 bucket. It allows
access to a bucket as though it were a local file system. It is
useful for publishing static web data that can be read easily by a
browser, or for backing up private or shared data.

* <http://code.google.com/p/s3fs/wiki/FuseOverAmazon>

This fork is intended to work better when using `rsync` to copy data
to an S3 mount.


Changes from s3fs
-----------------

This fork has the following changes:

*   File metadata is cached in a SQLite database for faster access.
    File systems do lots of `getattr` calls, and each one normally
    requires a HEAD request to S3. Caching them locally improves
    performance a lot and reduces the number (and hence cost) of
    requests to Amazon.

    The original s3fs has the beginnings of in-memory stat caching,
    but it does not persist across mounts. For large file systems,
    losing the entire cache on a restart is costly.

*   `readdir` requests do *not* send off file attribute requests.
    The original code effectively issues a `getattr` request to S3
    for each file when directories are listed. The cache is not
    consulted, but the results are put in the cache.

    This behavior made listing directories ridiculously slow. It
    appears to have been an attempt to optimize (by priming the
    cache) that backfired. It wouldn't be the first time that a
    cache optimization has made things slower overall.

*   The MIME type of files is reset when files are renamed. This
    fixes a bug in s3fs that is particularly devastating for `rsync`
    users. `rsync` always writes to a temporary file, then renames
    it to the target name. Without this fix, MIME types were rarely
    correct, which confused browsers when looking at static content
    on an S3 archive.

*   By default, ACLs are set based on the file permission. If the
    file is publicly readable, the "public-read" ACL is used, which
    permits anyone to read the file (including web browsers). If
    not, it defaults to "private", which denies access to public
    browsers. Setting the "default_acl" option overrides this, and
    sets everything to the specified ACL.

*   MD5 sums are computed for all uploads. S3 verifies the checksum
    on the received data, ensuring that no data was corrupted in
    transit (at least not during uploads).


Quick start
===========

Start by installing the dependencies. In Ubuntu Linux, the following
commands should do the trick:

    sudo apt-get install build-essential pkg-config libxml2-dev
    sudo apt-get install libcurl4-openssl-dev libsqlite3-dev
    sudo apt-get install libfuse2 libfuse-dev fuse-utils

Next, download the latest source:

    git clone git://github.com/russross/s3fslite.git

Go into the source directory and build it:

    cd s3fslite
    make

If there are no errors, then you are ready to install the binary:

    sudo make install

This copies the executable into `/usr/bin` where it is ready to use.

I suggest also creating a directory to hold the attribute cache
databases:

    sudo mkdir -p /var/cache/s3fs

It is also convenient to put your Amazon credentials in a file. I
use `vim`, so the command would be:

    sudo vim /etc/passwd-s3fs

Substitute the name of your favorite editor (`gedit` is an easy
choice if you do not know what else to use).

Inside this file, put your access key and your secret access key
(log in to your Amazon S3 account to obtain these) in this format:

    ACCESSKEY:SECRETACCESSKEY


Mounting a file system
----------------------

You need a mount point for your file systems. This is just an empty
directory that acts as a place to mount the file system:

    sudo mkdir /mnt/myfilesystem

You only need to create this once. Put this directory where
`<mountpoint>` is specified below.

Starting with an empty bucket (or one that you have used with other
versions of s3fs already), mount it like this:

    sudo s3fs <bucket> <mountpoint> -o attr_cache=/var/cache/s3fs -o use_cache=/tmp -o allow_other

This mounts the file system with a file cache and allows all users
of the local machine to use the mount.

You should now be able to use it like a normal file system, subject
to some limitations discussed below.

To unmount it, make sure no terminal windows are open inside the
file system, no applications have files in it open, etc., then
issue:

    sudo umount <mountpoint>

To simplify mounting in the future, add a line to `/etc/fstab`.
Substituting your editor of choice for `vim`, do:

    sudo vim /etc/fstab

and add a line of the form:

    s3fs#<bucket> <mountpoint> fuse attr_cache=/var/cache/s3fs,use_cache=/tmp,allow_other 0 0

With that in place, you can mount it using:

    sudo mount <mountpoint>

and unmount it using:

    sudo umount <mountpoint>

You can also set it to automatically mount at boot time. See
`man fstab` for details.


Details
=======

The complete list of supported options is:

*   `accessKeyId=` specify the Amazon AWS access key (no default)

*   `secretAccessKey=` specify the Amazon AWS secret access key (no
    default)

*   `default_acl=` specify the access control level for files
    (default `public-read` for files with public read permissions,
    `private` for everything else).

*   `retries=` specify the maximum number of times a failed/timed
    out request should be retried (default `2`)

*   `use_cache=` specify the directory for (and enable) a file cache
    (default no cache)

*   `connect_timeout=` specify the timeout interval for request
    connections (default `2`)

*   `readwrite_timeout=` specify the timeout interval for read and
    write operations (default `10`)

*   `url=` specify the host to connect to (default
    `http://s3.amazonaws.com`)

*   `attr_cache=` specify the directory where the attribute cache
    database should be created and accessed (default current
    directory)


Dependencies
------------

In order to compile s3fslite, you will need the following libraries:

*   Kernel-devel packages (or kernel source) installed that is the
    SAME version of your running kernel

*   LibXML2-devel packages

*   CURL-devel packages (or compile curl from sources at:
    curl.haxx.se/ use 7.15.X)

*   GCC, GCC-C++

*   pkgconfig

*   FUSE (2.7.x)

*   FUSE Kernel module installed and running (RHEL 4.x/CentOS 4.x
    users read below)

*   OpenSSL-devel (0.9.8)

*   SQLite 3

These packages may have additional dependencies. For Ubuntu users,
the commands to install everything you need are given in the quick
start guide. For other users, use your packaging system to install
the necessary dependencies. Most compiler errors are due to missing
libraries.


Known Issues:
-------------

s3fslite should be working fine with S3 storage. However, There are
couple of limitations:

*   There is no full UID/GID support yet, everything looks as
    "`root`" and if you allow others to access the bucket, others
    can erase files. There is, however, permissions support built
    in.

*   Currently s3fs could hang the CPU if you have lots of time-outs.
    This is *not* a fault of s3fs but rather `libcurl`. This
    happends when you try to copy thousands of files in 1 session,
    it doesn't happend when you upload hundreds of files or less.

*   CentOS 4.x/RHEL 4.x users: if you use the kernel that shipped
    with your distribution and didn't upgrade to the latest kernel
    RedHat/CentOS gives, you might have a problem loading the
    "`fuse`" kernel. Please upgrade to the latest kernel (2.6.16 or
    above) and make sure "`fuse`" kernel module is compiled and
    loadable since FUSE requires this kernel module and s3fs
    requires it as well.

*   Moving/renaming/erasing files takes time since the whole file
    needs to be accessed first. A workaround could be to use cache
    support with the `-o use_cache` option.


License:
--------

s3fslite retains the original GPL v2 license that s3fs uses. See the
file `COPYING` for details.
