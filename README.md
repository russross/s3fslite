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

To protect your secret key, make the file only accessible by `root`:

    sudo chmod 600 /etc/passwd-s3fs


Mounting a file system
----------------------

You need a mount point for your file systems. This is just an empty
directory that acts as a place to mount the file system:

    sudo mkdir /mnt/myfilesystem

You only need to create this once. Put this directory where
`<mountpoint>` is specified below.

Starting with an empty bucket (or one that you have used with other
versions of s3fs already), mount it like this:

    sudo s3fs <bucket> <mountpoint> -o attr_cache=/var/cache/s3fs -o allow_other

This mounts the file system with the attribute cache database in
`/var/cache/s3fs` and allows all users of the local machine to use
the mount.

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

    s3fs#<bucket> <mountpoint> fuse attr_cache=/var/cache/s3fs,allow_other 0 0

With that in place, you can mount it using:

    sudo mount <mountpoint>

and unmount it using:

    sudo umount <mountpoint>

This will also cause it to automatically mount at boot time.


Attribute cache
---------------

If the attribute cache ever gets out of sync, simply delete the
database file. This is `/var/cache/s3fs/<bucketname>.sqlite` if you
set things up as recommended. If you are accessing a single bucket
from multiple machines, you must manage the cache yourself. You can
either delete the file each time you switch machines, or you can
copy it over. If you do the latter, you should unmount the bucket
before copying the file, and before copying it into its new
location. You should only have a bucket mounted from one place at a
time.

The database file compresses very nicely; compressing it and copying
it to another location (then decompressing it) is a viable solution.

When starting from a cold cache, you can just start using the system
and it will gradually build the cache up. If you are using it
interactively, it will be really slow at first, so I recommend
priming the cache first. Just do:

    find /mnt/myfilesystem

and go do something else while it runs. This will scan the entire
mount and load the attributes for every file into the cache. From
that point forward, using it interactively should be much more
pleasant.


Using `rsync`
-------------

When using `rsync` to upload data, I recommend using the `-a` option
(to sync file times, do recursive uploads, etc.) and the `-W`
option. `-W` instructs it to always copy whole files. Without it,
`rsync` will download the old version of a file and try to be clever
about updating it. Since this all happens in the local cache, you
do not save much, but you do incur the cost of downloading it. When
it transfers a whole file, it just deletes the old version.

For example, I typically set it up so that the directory I want to
upload has the same name as the mount point, say `myname`. If the
source is `~/myname` and the mount point is `/mnt/myname`, then I
use a command like this:

    rsync -avW --delete ~/myname /mnt/

The `--delete` option tells it to delete files in the target that
are not in the source, so be careful with this option. An
alternative is this:

    rsync -avW --delete ~/myname/ /mnt/myname/

Beware that this means something slightly different. This syncs all
of the files in `/myname/`, but does not sync the directory itself.
As a result, files missing from `~/myname/` will not be deleted from
`/mnt/myname/`.

S3's "eventually consistent" semantics can lead to some weird
behavior. `rsync` will sometimes report a file vanishing and other
problems. Wait 30 seconds or so and try again, and the problem will
usually fix itself. As an example, sometimes when you delete a file
it still shows up in directory listings, but reports a "File not
Found" error when you try to access it. This also happens frequently
when you do a `rm -r` over a medium to large directory structure. It
correctly deletes the files, then fails to delete the directory.
This is because S3 is still reporting the odd file as existing in a
directory listing, but it has already been deleted. Wait for a few
tens of seconds and it should fix itself.

`rsync` is nice because you can just repeat the command and it will
only worry about the things that did not work the first time.  With
the attribute cache, only a few requests are necessary (to look up
directory listings), so repeated `rsync` operations are pretty
cheap.


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

*   `connect_timeout=` specify the timeout interval for request
    connections (default `2`)

*   `readwrite_timeout=` specify the timeout interval for read and
    write operations (default `10`)

*   `url=` specify the host to connect to (default
    `http://s3.amazonaws.com`)

*   `attr_cache=` specify the directory where the attribute cache
    database should be created and accessed (default current
    directory)


Changes from s3fs
-----------------

This fork has the following changes:

*   S3fslite has a writeback cache that holds open files and files
    that were closed within the last few seconds. This absorbs many
    of the requests that otherwise take a round-trip each to S3. For
    example, when `rsync` creates a file, it creates it with a
    temporary name, writes the data, sets the mode, sets the owner,
    sets the times, and then moves it over to its permanent name.
    Without the writeback cache, each of these operations requires a
    round trip to the server. With it, everything happens locally
    until the final version is uploaded with all of its metadata.

    To force a sync, do an `ls` in any directory. The `readdir` call
    does a complete sync before retrieving the directory listing.

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
    for each file when directories are listed. The cache was not
    consulted, but the results were put in the cache.

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
    browsers. Setting the `default_acl` option overrides this, and
    sets everything to the specified ACL.

*   MD5 sums are computed for all uploads and downloads. S3 provides
    MD5 hash values on downloads, and verifies them on the received
    data for uploads, ensuring that no data is corrupted in transit.

*   The `use_cache` option has been removed. An on-disk cache is not
    currently supported, except for the short-term writeback cache.
    For AFS-style caching (which is more-or-less what s3fs uses), a
    seperate caching layer would be more appropriate.


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


Debugging
---------

s3fslite logs error and status messages to `/var/log/syslog`. To
make it display more messages, you can enable some debug flags:

*   `DEBUG` logs each VFS call that is made, e.g., `getattr`,
    `readdir`, `open`, `read`, `write`, etc.

*   `DEBUG_WIRE` logs each time it contacts S3. This can be useful
    for seeing how well the cache is working.

*   `DEBUG_CACHE` logs information about the writeback cache. This
    is fairly chatty output.

All of these messages go to `/var/log/syslog`, so open a terminal
and run:

    tail -f /var/log/syslog

To enable these flags, add the following to the `CPPFLAGS` line in
the `Makefile`:

    -DDEBUG -DDEBUG_WIRE -DDEBUG_CACHE

Then do a `make clean` and another `make` and `make install` to
rebuild it with the caching options.


Known Issues:
-------------

s3fslite should be working fine with S3 storage. However, There are
couple of limitations:

*   There is no full UID/GID support yet, everything looks as
    "`root`" and if you allow others to access the bucket, others
    can erase files. There is, however, permissions support built
    in.

*   CentOS 4.x/RHEL 4.x users: if you use the kernel that shipped
    with your distribution and didn't upgrade to the latest kernel
    RedHat/CentOS gives, you might have a problem loading the
    "`fuse`" kernel. Please upgrade to the latest kernel (2.6.16 or
    above) and make sure "`fuse`" kernel module is compiled and
    loadable since FUSE requires this kernel module and s3fs
    requires it as well.


License:
--------

s3fslite retains the original GPL v2 license that s3fs uses. See the
file `COPYING` for details.
