#ifndef TNT15_H__
#define TNT15_H__

enum {
	TNT_OP_INSERT =    13,
	TNT_OP_SELECT =    17,
	TNT_OP_UPDATE =    19,
	TNT_OP_DELETE =    21,
	TNT_OP_CALL   =    22,
	TNT_OP_PING   =    65280,
};

enum {
	TNT_FLAG_RETURN    = 0x01,
	TNT_FLAG_ADD       = 0x02,
	TNT_FLAG_REPLACE   = 0x04,
	TNT_FLAG_BOX_QUIET = 0x08,
	TNT_FLAG_NOT_STORE = 0x10,
};

enum {
	TNT_UPDATE_ASSIGN = 0,
	TNT_UPDATE_ADD,
	TNT_UPDATE_AND,
	TNT_UPDATE_XOR,
	TNT_UPDATE_OR,
	TNT_UPDATE_SPLICE,
	TNT_UPDATE_DELETE,
	TNT_UPDATE_INSERT,
};

typedef struct {
	uint32_t type;
	uint32_t len;
	uint32_t seq;
} tnt_hdr_t;

typedef struct {
	uint32_t type;
	uint32_t len;
	uint32_t seq;
	uint32_t code;
} tnt_res_t;

typedef struct {
	uint32_t ns;
	uint32_t flags;
} tnt_hdr_nsf_t;

typedef struct {
	uint32_t type;
	uint32_t len;
	uint32_t seq;
	uint32_t space;
	uint32_t flags;
} tnt_pkt_insert_t;

typedef tnt_pkt_insert_t tnt_pkt_delete_t;
typedef tnt_pkt_insert_t tnt_pkt_update_t;

typedef struct {
	uint32_t type;
	uint32_t len;
	uint32_t seq;
	uint32_t space;
	uint32_t index;
	uint32_t offset;
	uint32_t limit;
	uint32_t count;
} tnt_pkt_select_t;


typedef struct {
	uint32_t type;
	uint32_t len;
	uint32_t seq;
	uint32_t flags;
} tnt_pkt_call_t;

typedef struct {
	uint32_t len;
	char   * data;
} tnt_pkt_field_t;

typedef struct {
	uint32_t          count;
	tnt_pkt_field_t * fields;
} tnt_pkt_tuple_t;

typedef struct {
	int type;
	int len;
	int seq;

	int code;

	struct {
		int   len;
		char *str;
	} error;

	int count;
	tnt_pkt_tuple_t * tuples;
} tnt_pkt_reply_t;

#endif