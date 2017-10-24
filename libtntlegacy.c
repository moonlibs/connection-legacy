/*
	legacy proto module
	compile with:
		gcc -Wall -shared -fPIC -o libtntlegacy.so libtntlegacy.c
		gcc -Wall -shared -fPIC -o libtntlegacy.dylib libtntlegacy.c

	test as binary:
		gcc -Wall -DTEST -o tntlegacy libtntlegacy.c && ./tntlegacy
*/

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#include "portable_endian.h"

// #define TNT_OP_INSERT      13
// #define TNT_OP_SELECT      17
// #define TNT_OP_UPDATE      19
// #define TNT_OP_DELETE      21
// #define TNT_OP_CALL        22
// #define TNT_OP_PING        65280

// #define TNT_FLAG_RETURN    0x01
// #define TNT_FLAG_ADD       0x02
// #define TNT_FLAG_REPLACE   0x04
// #define TNT_FLAG_BOX_QUIET 0x08
// #define TNT_FLAG_NOT_STORE 0x10

#include "tntlegacy.h"


typedef
	union {
		char     *c;
		uint32_t *i;
		uint64_t *q;
		uint16_t *s;
	} uniptr;

unsigned char allowed_format[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
	0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
	1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


typedef struct {
	char    def;
	char   *f;
	size_t size;
} tnt_unpack_format;

static inline char * varint(char *buf, uint32_t value) {
	if ( value >= (1 << 7) ) {
		if ( value >= (1 << 14) ) {
			if ( value >= (1 << 21) ) {
				if ( value >= (1 << 28) ) {
					*(buf++) = (value >> 28) | 0x80;
				}
				*(buf++) = (value >> 21) | 0x80;
			}
			*(buf++) = ((value >> 14) | 0x80);
		}
		*(buf++) = ((value >> 7) | 0x80);
	}
	*(buf++) = ((value) & 0x7F);
	return buf;
}

int tnt_varint_size(uint32_t value) {
	if (value < (1 << 7 )) return 1;
	if (value < (1 << 14)) return 2;
	if (value < (1 << 21)) return 3;
	if (value < (1 << 28)) return 4;
	                       return 5;
}

static int tnt_field_size(uint32_t value) {
	if (value < (1 << 7 )) return value + 1;
	if (value < (1 << 14)) return value + 2;
	if (value < (1 << 21)) return value + 3;
	if (value < (1 << 28)) return value + 4;
	                       return value + 5;
}

//	printf("buffer_check %d vs %d\n",((out)-(ptr)) + (outsz) , (need));
#define buffer_check(out,outsz,ptr,need,error) do { \
	if (((out)-(ptr)) + (int)(outsz) < (int)(need)) { \
		error = "Too small buffer for this packet"; \
		return false; \
	} \
} while (0)


/*

lib.ping()

 */

bool tnt_ping( char *out, size_t* outsz, char **error, uint32_t req_id ) {
	buffer_check(out, *outsz, out, sizeof(tnt_hdr_t), *error);
	tnt_hdr_t * s = (tnt_hdr_t *) out;
	s->type  = htole32( TNT_OP_PING );
	s->seq = htole32( req_id );
	s->len   = 0;
	*outsz   = sizeof(tnt_hdr_t);
	return true;
}

/*

tuple:
	(w/a*)*


fields = ffi.new('tnt_pkt_field_t[?]',count)
fields[1].len = ..
fields[1].data = ..

tuple = ffi.new('tnt_pkt_tuple_t[?]',1)
tuple.count = 1
tuple.fields = fields

lib.call(out, outsz, err,
	123, 0, method, #method, tuple)


*/

bool tnt_call( char *out, size_t* outsz, char **error,
	uint32_t req_id, uint32_t flags, char * proc, size_t procsz, tnt_pkt_tuple_t * tuple  )
{
	register uniptr p;
	tnt_pkt_call_t *h = (tnt_pkt_call_t *) out;
	p.c = (char *)(h+1);

	buffer_check(out, *outsz, p.c,
		tnt_field_size(procsz) +
		4 + // cardinality
		tuple->count * 1 // at least minimal w/ (1) for every field
	, *error);

	p.c = varint( p.c, procsz );
	memcpy( p.c, proc, procsz );
	p.c += procsz;
	
	*(p.i++) = htole32( tuple->count );
	int i;
	for (i=0; i < tuple->count; i++) {
		if (tuple->fields[i].len) {
			buffer_check(out, *outsz, p.c, tnt_field_size(tuple->fields[i].len), *error);
			p.c = varint( p.c, tuple->fields[i].len );
			memcpy( p.c, tuple->fields[i].data, tuple->fields[i].len );
			p.c += tuple->fields[i].len;
		}
		else {
			buffer_check(out, *outsz, p.c, 1, *error);
			*(p.c++) = 0;
		}
	}

	*outsz = p.c - out;
	// printf("Out size: %d / %x\n",*outsz, *outsz - sizeof( tnt_hdr_t ));

	h->type   = htole32( TNT_OP_CALL );
	h->seq    = htole32( req_id );
	h->flags  = htole32( flags );
	h->len    = htole32( *outsz - sizeof( tnt_hdr_t ) );

	return true;
}


bool tnt_reply_header(const char **data, ssize_t size, tnt_pkt_reply_t *reply)
{
	const char *ptr, *end;
	memset(reply, 0, sizeof(tnt_pkt_reply_t));
	if ( size < sizeof(tnt_hdr_t) ) { return 0; }

	tnt_res_t *hd = (tnt_res_t *) *data;
	reply->len  = le32toh( hd->len );
	ptr = *data + 12;

	if ( size < reply->len + sizeof(tnt_hdr_t) ) {
		return 0;
	}
	end = ptr + reply->len;

	reply->type = le32toh( hd->type );
	reply->code = le32toh( hd->code );
	reply->seq  = le32toh( hd->seq );

	// (*data) += 12;

	if (reply->len >= 4 ) { // have code in response
		reply->code = le32toh( hd->code );
		if (reply->code == 0) {
			if (reply->len >= 8) { // have count in response
				reply->count = le32toh( hd->count );
				(*data) += sizeof(tnt_hdr_t) + 8; // set ptr to the start of tuples
				reply->data = (char *) *data;
				return true;
			}
			else {
				(*data) += sizeof(tnt_hdr_t) + reply->len;
			}
		}
		else {
			ptr += 4;
			reply->error.len = end > ptr ? end - ptr - 1 : 0;
			reply->error.str = (char *) ptr;
		}
	}

	// fast forward to the end of packet
	(*data) += sizeof(tnt_hdr_t) + reply->len;

	return true;
}

bool tnt_reply_tuple(const char **data, ssize_t size, tnt_reply_tuple_t *tuple)
{
	tuple->size  = le32toh( ( *(uint32_t *) *data ) ); *data +=4;
	tuple->count = le32toh( ( *(uint32_t *) *data ) ); *data +=4;
	tuple->next  = (char *) *data;

	// if (tuple->size > size) {
	// 	// fprintf(stderr,"intersection type 1 in tuple: data=%p, size = %u, end = %p\n", data, tsize, end);
	// 	return false
	// }
	// return true
	return tuple->size <= size;
}

bool tnt_reply_field(const char **data, ssize_t size, const char ** field, ssize_t * len)
{
	char *ptr = (char *)*data;
	char *end = ptr + size;
	ssize_t fsize = 0;
	do {
		fsize = ( fsize << 7 ) | ( *ptr & 0x7f );
	} while ( *ptr++ & 0x80 && ptr < end );
	
	if (ptr + fsize > end) {
		// fprintf(stderr,"intersection type 1 in tuple: data=%p, size = %u, end = %p\n", data, tsize, end);
		return false;
	}
	*len = fsize;
	*field = (char *) ptr;
	*data = ptr + fsize;
	return true;
}

#include "xd.h"

char * hexdump(char *data, size_t size, xd_conf *cf) {
	return xd(data, size, cf);
}

#ifdef TEST
#include <errno.h>
#include <stdio.h>

#include "xd.h"

int main () {
	// printf("Test\n");
	// char mytest[] = "1234567890\xffZ";
	// printf("%s",xd(mytest,sizeof(mytest),0));

	char test[32];
	size_t tsz = sizeof(test);
	char *errstr;

	if( tnt_ping(test, &tsz, &errstr,0xdeadbeaf) ) {
		char * dump = xd(test,tsz,0);
		if (dump) {
			printf("Encoded: %zu:\n%s\n",tsz,dump);
			free(dump);
		}
	}
	else {
		printf("Failed: %s\n", errstr);
	}

	tsz = sizeof(test);
	tnt_pkt_field_t fld = { 4, "Test" };
	tnt_pkt_tuple_t tup = { 1, &fld };

	if( tnt_call(test, &tsz, &errstr,0xdeadbeaf, 0, "method", 6, &tup) ) {
		char * dump = xd(test,tsz,0);
		if (dump) {
			printf("Encoded: %zu:\n%s\n",tsz,dump);
			free(dump);
		}
	}
	else {
		printf("Failed: %s\n", errstr);
	}
	printf("Done\n");
	// exit(0);
	return 0;
}

#endif
