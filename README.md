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

*   `acl=` specify the access control level for files (default
    `public-read` for files with public read permissions, `private`
    for everything else).

*   `retries=` specify the maximum number of times a failed/timed
    out request should be retried in addition to the initial attempt
    (default `2`)

*   `connect_timeout=` specify the timeout interval for request
    connections (default `2`)

*   `readwrite_timeout=` specify the timeout interval for read and
    write operations (default `10`)

*   `url=` specify the host to connect to (default
    `http://%s.s3.amazonaws.com`). If you want to use HTTPS instead
    of HTTP to get secure transfers, specify
    `url=https://%s.s3.amazonaws.com` as a mount option.

    The host URL should contain the bucket name as in a virtual
    host-style URL, or put `%s` in the host string and the bucket
    name will be substituted in for you.

*   `attr_cache=` specify the directory where the attribute cache
    database should be created and accessed (default current
    directory)

*   `dir_cache=` enable/disable directory caching. With this
    enabled, all metadata queries will be confined to the local
    cache if the file system believes it has up-to-date entries for
    every file in the directory. When creating a new file or trying
    to open a file that does not exist, this saves a round trip to
    the server. To decide if a directory is completely represented,
    it checks each time a readdir operation is invoked to see if
    every file the server names has a metadata cache entry. Future
    readdir operations are also satisfied by the cache. (default
    `true`).

*   `dir_cache_reset=` force the list of completely cached
    directories (see `dir_cache=` above) to be reset at file system
    mount time (default `true`).

*   `writeback_cache=` specify the directory where the write-back
    cache temporary files should be created (default `/tmp`). Files
    are unlinked as soon as they are created, so you will not
    generally see anything listed in the given directory, but the
    storage of that file system will still be used.

*   `writeback_delay=` specify the number of seconds a closed file
    should be cached before changes are uploaded to S3
    (default `5`).


Changes from s3fs
-----------------

This fork has the following changes:

*   S3fslite has a write-back cache that holds open files and files
    that were closed within the last few seconds. This absorbs many
    of the requests that otherwise take a round-trip each to S3. For
    example, when `rsync` creates a file, it creates it with a
    temporary name, writes the data, sets the mode, sets the owner,
    sets the times, and then moves it over to its permanent name.
    Without the write-back cache, each of these operations requires
    a round trip to the server. With it, everything happens locally
    until the final version is uploaded with all of its metadata.

    To force a sync, do an `ls` in the directory of interest. The
    `readdir` call does a sync on every file in the directory before
    retrieving the directory listing.

*   File metadata is cached in a SQLite database for faster access.
    File systems do lots of `getattr` calls, and each one normally
    requires a HEAD request to S3. Caching them locally improves
    performance a lot and reduces the number (and hence cost) of
    requests to Amazon.

    The original s3fs has the beginnings of in-memory stat caching,
    but it does not persist across mounts. For large file systems,
    losing the entire cache on a restart is costly.

*   Directories can be renamed. This requires renaming all of the
    directory's children, grandchildren, etc., so it can be a slow
    operation, but it works. Files are all copied at the server, not
    by downloading them and re-uploading them, the same as for
    metadata updates, regular renames, and links.

    Directories with open files (this includes any descendents)
    cannot be renamed. Open files cannot be renamed either.

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
    currently supported, except for the short-term write-back cache.
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

*   `DEBUG_CACHE` logs information about the write-back cache. This
    is fairly chatty output.

All of these messages go to `/var/log/syslog`, so open a terminal
and run:

    tail -f /var/log/syslog

To enable these flags, add the following to the `CPPFLAGS` line in
the `Makefile`:

    -DDEBUG -DDEBUG_WIRE -DDEBUG_CACHE

Then do a `make clean` and another `make` and `make install` to
rebuild it with the caching options.


The write-back cache
--------------------

When a file is opened, it is transferred from S3 to a local file.
This is created in `/tmp` and immediately unlinked, so it is not
visible in the file system and will automatically be deleted when
closed (or if the program crashes).

All read/write operations take place on the cached copy of the file.
It is held in the cache and not synchronized with the server (except
in some special cases discussed below) until the file is closed and
has not been touched for 5 seconds. Metadata updates reset the
clock, so `chmod` and `chown` operations keep the item cached as
well.

A file is normally only flushed to the server when it is closed and
has been idle for 5 seconds. This covers file renames and deletes as
well. This is designed for `rsync`, which writes the data to a
temporary file, then sets its mode, ownership, and times, then
renames it to its final name. All of this happens in the cache, and
the final version of the file complete with metadata is pushed to
the server in one transfer.

`readdir` operations are never cached, so they have the potential to
pierce the abstraction and observe unsynced operations. To prevent
this, *all* files in the cache are synced before a `readdir`
operation. This is the simplest way to force a sync and make sure
all of the data has been written out: just run `ls` in any directory
inside the mounted file system. `rmdir` operations also force a sync
for the same reason; non-empty directories cannot be removed, so a
sync is performed first to make sure any recent deletes have been
pushed to the server.

All of this means that operations (like `rsync`) will often be very
fast for the first 5 seconds or so, and then suddenly slow down. The
whole server uses a big ol' lock for synchronization, so only a
single operation can be happening at once. When the thread that
flushes the cache obtains the lock, it holds on to it until the
cache has been cleared (to the 5 second limit). This means that
while it is catching up, nothing else happens, preventing the
backlog from getting too long.

As a result, the server is usually within about 10 or 20 seconds of
being current with the cache. A sync is also forced when the file
system shuts down normally.

To observe how all of this works, enable all of the debugging logs
(see the "Debugging" section).


Known Issues:
-------------

s3fslite works fine with S3 storage. However, There are couple of
limitations:

*   File permissions are not enforced. Files are always created as
    the user who mounts the file system (normally `root`), but
    anyone can change anything.

*   Hard links are faked. They are implemented by doing a simple
    (server-side) copy. This is great for most cases (notably when
    using hard links as a way to move a file to another directory),
    but it is not the same as a real hard link. If a file is open
    when it is linked, the two versions actually do share storage
    (and updates), but only until one of them is flushed from the
    cache. I do not recommend relying on this behavior.

*   This note comes from the original s3fs: CentOS 4.x/RHEL 4.x
    users: if you use the kernel that shipped with your distribution
    and didn't upgrade to the latest kernel RedHat/CentOS gives, you
    might have a problem loading the "`fuse`" kernel. Please upgrade
    to the latest kernel (2.6.16 or above) and make sure "`fuse`"
    kernel module is compiled and loadable since FUSE requires this
    kernel module and s3fs requires it as well.

*   S3fslite is mainly intended for publishing data to S3. It does
    not provide general local caching, nor services like encryption
    or compression.  Some of these issues can be addressed with
    existing systems:

    *   Encryption: if you want file-by-file encryption (as opposed
        to encrypting an entire block device), you can plug in EncFS
        with s3fslite. This acts as a layer on top of any other file
        system and provides encryption services.

    *   Caching: Systems like FS-Cache and CacheFS promise to do the
        same thing for caching. You mount s3fslite, then you mount
        another layer on top of it that provides caching.

    *   Compression: FuseCompress works on the same basic model as
        the others, compressing data for a file system that does not
        have direct support for compression.

    I have not tried these solutions (I just googled for them), and
    would welcome reports about whether or not (or how well) they
    work.


Source code tour
----------------

There are six main source files:

1.  `common.cpp`: utility functions and global variables.

2.  `fileinfo.cpp`: a simple class to hold file attributes.

3.  `attrcache.cpp`: the SQLite attribute caching. This cache is
    intended to reflect the current state of the server, and it
    knows nothing about the write-back cache.

4.  `s3request.cpp`: wire requests to Amazon S3 using `libcurl`.
    `s3request` is ignorant of any caching, and is purely concerned
    with forming requests and gathering responses.

5.  `filecache.cpp`: the write-back cache. This cache draws from and
    updates the attribute cache when necessary, and issues S3
    requests when needed. In that sense, it sits right below the
    main file system operations layer.

6.  `s3fs.cpp`: the FUSE file system operations, along with startup
    and shutdown code. This code depends on and knows about
    everything else.


License:
--------

s3fslite retains the original GPL v2 license that s3fs uses. See the
file `COPYING` for details.
