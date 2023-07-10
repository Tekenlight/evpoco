0.  Download postgresql-15.3.tar.gz from https://ftp.postgresql.org/pub/source/v15.3/postgresql-15.3.tar.gz
1.  CFLAGS=-fPIC configure
2.  GSSAPI disabled, LDAP disabled, SSL disabled, by default
3.  cd src/interfaces/libpq/
4.  make
5.  make install DESTDIR=$HOME/postgresql/build-15.3
6.  cd src/bin/pg_config
7.  make install DESTDIR=$HOME/postgresql/build-15.3
8.  cd src/backend
9.  make generated-headers
10. cd src/include
11. make install DESTDIR=$HOME/postgresql/build-15.3
12. cd src/common
13. make install DESTDIR=$HOME/postgresql/build-15.3
14. cd src/port
15. make install DESTDIR=$HOME/postgresql/build-15.3
