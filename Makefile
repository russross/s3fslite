SOURCES=common.cpp fileinfo.cpp attrcache.cpp filecache.cpp s3request.cpp s3fs.cpp

CPP=g++

CPPFLAGS=-Wall -Wextra -Wno-unused-parameter -Werror -Os \
	$(shell pkg-config fuse --cflags) \
	$(shell pkg-config libcurl --cflags) \
	$(shell pkg-config sqlite3 --cflags) \
	$(shell xml2-config --cflags)

LDFLAGS=$(shell pkg-config fuse --libs) \
	$(shell pkg-config libcurl --libs) \
	$(shell pkg-config sqlite3 --libs) \
	$(shell xml2-config --libs) \
	-lcrypto

all:	s3fs

s3fs:	$(SOURCES:.cpp=.o)
	g++ -o s3fs $(SOURCES:.cpp=.o) $(CPPFLAGS) $(LDFLAGS)

install: all
	cp -f s3fs /usr/bin

clean:
	rm -f s3fs *.o *.gch
