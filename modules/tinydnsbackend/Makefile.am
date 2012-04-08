AM_CPPFLAGS=@THREADFLAGS@
lib_LTLIBRARIES = libtinydnsbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

INCLUDES=@CDB_CFLAGS@


bind-dnssec.schema.sqlite3.sql.h: ../../pdns/bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[]=' ; sed 's/$$/"/g' ../../pdns/bind-dnssec.schema.sqlite3.sql | sed 's/^/"/g'  ; echo ';' ) > $@


libtinydnsbackend_la_SOURCES=cdb.cc cdb.hh tinydnsbackend.cc tinydnssecbackend.cc tinydnsbackend.hh bind-dnssec.schema.sqlite3.sql.h
libtinydnsbackend_la_LDFLAGS=-module -avoid-version @CDB_LIBS@

