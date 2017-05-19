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
} unpack_format;

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

int varint_size(uint32_t value) {
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

bool ping( char *out, size_t* outsz, char **error, uint32_t req_id ) {
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

bool call( char *out, size_t* outsz, char **error,
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
	
	for (int i=0; i < tuple->count; i++) {
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

size_t parse_reply( char *out, size_t* outsz, char **error,
	const char *data, size_t size, const unpack_format * format)
{
	const char *ptr, *beg, *end;

	if ( size < sizeof(tnt_hdr_t) ) {
		goto shortread;
	}

	beg = data;
	tnt_res_t *hd = (tnt_res_t *) data;
	uint32_t len  = le32toh( hd->len );

	if ( size < len + sizeof(tnt_hdr_t) ) {
		goto shortread;
	}

	tnt_pkt_reply_t * reply = calloc(1,sizeof(tnt_pkt_reply_t));

	reply->type = le32toh( hd->type );
	reply->code = le32toh( hd->code );
	reply->seq  = le32toh( hd->seq );
	
	data += sizeof(tnt_res_t);
	end = data + len - 4;
	
	switch (reply->type) {
		case TNT_OP_PING:
			return data - beg;
		case TNT_OP_UPDATE:
		case TNT_OP_INSERT:
		case TNT_OP_DELETE:
		case TNT_OP_SELECT:
		case TNT_OP_CALL:
			if (reply->code != 0) {
				reply->error.len = end > data ? end - data - 1 : 0;
				reply->error.str = (char *) data;
				data = end;
				break;
			}
			if (data == end) {
				// result without tuples
				break;
			}
			
			reply->count = le32toh( ( *(uint32_t *) data ) );
			data += 4;
			
			if (data >= end) {
				// result without tuples
				if (reply->count > 0) {
					fprintf(stderr, "Reply %d to %d contains count:%d != 0 but have no data\n", reply->seq, reply->type, reply->count);
					reply->count = 0;
				}
				break;
			}
			
			int i,k;

			reply->tuples = calloc(reply->count, sizeof(tnt_pkt_tuple_t));

			for ( i = 0; i < reply->count; i++ ) {
				uint32_t tsize = le32toh( ( *(uint32_t *) data ) ); data += 4;
				tnt_pkt_tuple_t * tuple = &reply->tuples[i];

				if (data + tsize > end) {
					fprintf(stderr,"intersection type 1 in tuple: data=%p, size = %u, end = %p\n", data, tsize, end);
					goto intersection;
				}
				uint32_t cardinality = le32toh( ( *(uint32_t *) data ) ); data +=4;
				
				tuple->count = cardinality;
				tuple->fields = calloc(cardinality, sizeof(tnt_pkt_field_t));
				
				ptr = data;
				data += tsize;
				size -= tsize;
				
				for ( k=0; k < cardinality; k++ ) {
					unsigned int fsize = 0;
					do {
						fsize = ( fsize << 7 ) | ( *ptr & 0x7f );
					} while ( *ptr++ & 0x80 && ptr < end );
					
					if (ptr + fsize > end) {
						fprintf(stderr,"intersection type 1 in tuple: data=%p, size = %u, end = %p\n", data, tsize, end);
						goto intersection;
					}
					
					tuple->fields[k].len = fsize;
					tuple->fields[k].data = (char *) ptr;

					ptr += fsize;
				};
			}
			break;
		default:
			reply->code = 10; // ER_UNSUPPORTED
			reply->error.str =        "Unknown type of operation";
			reply->error.len = strlen("Unknown type of operation");
			return end - beg;
	}
	return end - beg;
	
	intersection:
		reply->code = 8; //ER_UNUSED8
		reply->error.str =        "Nested structure intersect packet boundary";
		reply->error.len = strlen("Nested structure intersect packet boundary");
		return end - beg;
	shortread:
		return 0;

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

	if( ping(test, &tsz, &errstr,0xdeadbeaf) ) {
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

	if( call(test, &tsz, &errstr,0xdeadbeaf, 0, "method", 6, &tup) ) {
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
