local obj = require 'obj'
local log = require 'log'
local connection = require 'connection'

local ffi = require 'ffi'
local C = ffi.C
-- local lib = ffi.load('libtntlegacy.so')
local lib = ffi.load(package.searchpath('libtntlegacy', package.cpath), true)


local fiber = require 'fiber'

function ffi.typedef(t,def)
	if not pcall(ffi.typeof,t) then
		local r,e = pcall(ffi.cdef,def)
		if not r then error(e,2) end
	end
	return ffi.typeof(t)
end

function ffi.fundef(n,def,src)
	src = src or ffi.C
	local f = function(src,n) return src[n] end
	if not pcall(f,src,n) then
		local r,e = pcall(ffi.cdef,def)
		if not r then error(e,2) end
	end
	local r,e = pcall(f,src,n)
	if not r then
		error(e,2)
	end
	return r
end

local tnt_hdr_t = ffi.typedef("tnt_hdr_t",[[
	typedef struct {
		uint32_t type;
		uint32_t len;
		uint32_t seq;
	} tnt_hdr_t;
]])

local tnt_res_t = ffi.typedef("tnt_res_t",[[
	typedef struct {
		uint32_t type;
		uint32_t len;
		uint32_t seq;
		uint32_t code;
		uint32_t count;
	} tnt_res_t;
]])

-- ffi.typedef("tnt_pkt_insert_t",[[
-- 	typedef struct {
-- 		uint32_t type;
-- 		uint32_t len;
-- 		uint32_t seq;
-- 		uint32_t space;
-- 		uint32_t flags;
-- 	} tnt_pkt_insert_t;
-- 	typedef tnt_pkt_insert_t tnt_pkt_delete_t;
-- 	typedef tnt_pkt_insert_t tnt_pkt_update_t;
-- ]])
-- ffi.typedef("tnt_pkt_select_t",[[
-- 	typedef struct {
-- 		uint32_t type;
-- 		uint32_t len;
-- 		uint32_t seq;
-- 		uint32_t space;
-- 		uint32_t index;
-- 		uint32_t offset;
-- 		uint32_t limit;
-- 		uint32_t count;
-- 	} tnt_pkt_select_t;
-- ]])
local tnt_pkt_call_t = ffi.typedef("tnt_pkt_call_t",[[
	typedef struct {
		uint32_t type;
		uint32_t len;
		uint32_t seq;
		uint32_t flags;
	} tnt_pkt_call_t;
]])
local tnt_pkt_field_t = ffi.typedef("tnt_pkt_field_t",[[
	typedef struct {
		uint32_t len;
		char   * data;
	} tnt_pkt_field_t;
]])
local tnt_pkt_tuple_t = ffi.typedef("tnt_pkt_tuple_t",[[
	typedef struct {
		uint32_t          count;
		tnt_pkt_field_t * fields;
	} tnt_pkt_tuple_t;
]])

-- local tnt_pkt_reply_t = ffi.typedef("tnt_pkt_reply_t",[[
-- 	typedef struct {
-- 		int type;
-- 		int len;
-- 		int seq;

-- 		int code;

-- 		struct {
-- 			int   len;
-- 			char *str;
-- 		} error;

-- 		int count;
-- 		tnt_pkt_tuple_t * tuples;
-- 	} tnt_pkt_reply_t;
-- ]])

local tnt_pkt_reply_t = ffi.typedef("tnt_pkt_reply_t",[[
	typedef struct {
		int type;
		int len;
		int seq;

		int code;

		union {
			struct {
				int   len;
				char *str;
			} error;
			struct {
				int    count;
				char * data;
			};
		};
	} tnt_pkt_reply_t;
]])

local tnt_reply_tuple_t = ffi.typedef("tnt_reply_tuple_t",[[
	typedef struct {
		int size;
		int count;
		char *next;
	} tnt_reply_tuple_t;
]])


-- ffi.fundef("varint_size",[[
-- 	int varint_size(uint32_t value);
-- ]], lib)

ffi.fundef("tnt_call",[[
	bool tnt_call( char *out, size_t* outsz, char **error,
		uint32_t req_id, uint32_t flags, const char * proc,
		size_t procsz, tnt_pkt_tuple_t * tuple  );
]], lib)

-- ffi.fundef("tnt_reply",[[
-- 	size_t tnt_reply( tnt_pkt_reply_t *reply, const char *data, size_t size);
-- ]], lib)

ffi.fundef("tnt_reply_header",[[
	bool tnt_reply_header(char **data, ssize_t size, tnt_pkt_reply_t *reply);
]], lib)

ffi.fundef("tnt_reply_tuple",[[
	bool tnt_reply_tuple(char **data, ssize_t size, tnt_reply_tuple_t *tuple);
]], lib)

ffi.fundef("tnt_reply_field",[[
	bool tnt_reply_field(char **data, ssize_t size, char **field, ssize_t *len);
]], lib)



ffi.fundef("TNT_OP_INSERT",[[
	enum {
		TNT_OP_INSERT = 13,
		TNT_OP_SELECT = 17,
		TNT_OP_UPDATE = 19,
		TNT_OP_DELETE = 21,
		TNT_OP_CALL   = 22,
		TNT_OP_PING   = 65280,
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
]], lib)

ffi.cdef[[
	typedef struct {
		uint8_t row;
		uint8_t hpad;
		uint8_t cpad;
		uint8_t hsp;
		uint8_t csp;
		uint8_t cols;
	} xd_conf;
	char * hexdump(const char *data, size_t size, xd_conf *cf);
	void free (void *);
]]

local function xd( data )
	local buf = lib.hexdump(data,#data,nil);
	local rv
	if buf then
		rv = ffi.string(buf)
		ffi.C.free(buf)
	else
		error("Failed")
	end
	return rv
end

local function dump(x)
	local j = require'json'.new()
	j.cfg{
		encode_use_tostring = true;
	}
	return j.encode(x)
end

local M = obj.class({ debug = {} },'connection.legacy',connection)

local C2R = {
	[C.TNT_OP_PING]      = 'ping',
	[C.TNT_OP_INSERT]    = 'insert',
	[C.TNT_OP_SELECT]    = 'select',
	[C.TNT_OP_UPDATE]    = 'update',
	[C.TNT_OP_DELETE]    = 'delete',
	[C.TNT_OP_CALL]      = 'call',
}

-- static vars. must be used only without yield

local sz_ptr = ffi.new('size_t [1]');
local char_ptr = ffi.new('char *[?]',1);
local tuple_r = ffi.new('tnt_reply_tuple_t')

local tuple = ffi.new('tnt_pkt_tuple_t[?]',1)
-- local fixbuf = ffi.new('char[?]',4096)
local reply = ffi.new('tnt_pkt_reply_t')
local ptr = ffi.new('char *[3]')
local fld = ffi.new('char *[1]')

local seq = 0
function M.seq()
	seq = seq < 0xffffffff and seq + 1 or 1
	return seq
end

function M:_init(...)
	-- getmetatable( self.__index ).__index.init( self,... )
	self:super(M, '_init')(...)
	self.req = setmetatable({},{__mode = "kv"})
end

function M:_cleanup(e)
	-- getmetatable( self.__index ).__index._cleanup( self,e )
	self:super(M, '_cleanup')(e)
	for k,v in pairs(self.req) do
		if type(v) ~= 'number' then
			v:put(false)
		end
		self.req[k] = nil
	end
end

function M:_buffer_state()
	if self.avail >= 12 then
		local hdr = ffi.cast('tnt_hdr_t *',self.rbuf)
		print("[I] BUF[", self.avail, ']: ', C2R[hdr.type],'#',hdr.seq,' + ', ( tonumber(self.avail) - 12 ), ' of ' , hdr.len)
	elseif self.avail >= 8 then
		local hdr = ffi.cast('tnt_hdr_t *',self.rbuf)
		print("[I] BUF[", self.avail, ']: ', C2R[hdr.type],'#? + ',tonumber(self.avail) - 12, ' of ' , hdr.len)
	elseif self.avail >= 4 then
		local hdr = ffi.cast('tnt_hdr_t *',self.rbuf)
		print("[I] BUF[", self.avail, ']: ', C2R[hdr.type],'#? + ?')
	else
		print("[I] BUF[", self.avail,']')
	end
end

function M:on_read(is_last)
	local pkoft = 0
	local avail = self.avail
	-- print("on_read ",self.avail)
	if M.debug.verbose then
		print("read\n"..xd(ffi.string(self.rbuf,self.avail)))
	end

	if M.debug.rbuf then self:_buffer_state() end

	ptr[2] = self.rbuf+self.avail -- end of data

	while true do
		ptr[0] = self.rbuf + pkoft -- parse start
		-- print(ptr,ptr[0],ptr[1],ptr[1])
		if lib.tnt_reply_header( ptr, ptr[2]-ptr[0], reply ) then
			local res;
			-- print("something parsed, left ",ptr[2]-ptr[0])

			pkoft = pkoft + 12 + reply.len
			ptr[1] = self.rbuf + pkoft -- end of packet

			-- print(dump({
			-- 	type = reply.type;
			-- 	code = reply.code;
			-- 	len  = reply.len;
			-- 	seq  = reply.seq;
			-- 	count = reply.code == 0 and reply.count or nil;
			-- 	error = reply.code > 0 and ffi.string(reply.error.str,reply.error.len) or nil;
			-- }));

			local res = (function()
				if reply.code == 0 then
					local tuples = {}
					for t = 0,reply.count-1 do
						if lib.tnt_reply_tuple( ptr, ptr[1]-ptr[0], tuple_r ) then
							-- print(dump{
							-- 	size = tuple_r.size,
							-- 	count = tuple_r.count,
							-- })
							local row = {}
							for f = 0,tuple_r.count-1 do
								if lib.tnt_reply_field( ptr, ptr[1]-ptr[0], char_ptr, sz_ptr ) then
									-- print("got field",f, sz_ptr[0], ffi.string( char_ptr[0],sz_ptr[0] ))
									table.insert(row, ffi.string( char_ptr[0],sz_ptr[0] ))
								else
									log.error("tuple %s field %s boundary intersection, have:%s",t+1, f+1, ptr[1]-ptr[0])
									return { 8, "Field boundary intersection" }
								end
							end
							table.insert(tuples,row)
						else
							-- in case of false, skip tuple and log error
							log.error("tuple %s boundary intersection need:%s, have:%s",(t+1), tuple_r.size, ptr[1]-ptr[0])
							return { 8, "Tuple boundary intersection" }
						end
					end
					return { 0, tuples }
				else
					return { tonumber(reply.code), ffi.string( reply.error.str, reply.error.len ) }
				end
			end)()

			if M.debug.verbose then
				print(dump(res))
			end

			if type(self.req[ reply.seq ]) ~= 'number' then
				self.req[ reply.seq ]:put(res)
			else
				log.info(
					"Received timed out %s#%s after %0.4fs",
					C2R[ reply.type ], reply.seq, fiber.time() - self.req[ reply.seq ]
				)
			end
			self.req[ reply.seq ] = nil

		else
			break
		end
	end
	self.avail = self.avail - pkoft

	return
end

-- maybe later I compare the speed with the following code...

-- function M:on_read(is_last)
-- 	local pkoft = 0
-- 	local avail = self.avail
-- 	-- print("on_read ",self.avail)
-- 	print("read\n"..xd(ffi.string(self.rbuf,self.avail)))

-- 	if M.debug.rbuf then self:_buffer_state() end


-- 	while self.avail - pkoft >= 12 do
-- 		local hdr = ffi.cast('tnt_res_t *',self.rbuf + pkoft)
-- 		if self.avail - pkoft >= 12 + hdr.len then
-- 			pkoft = pkoft + 12
-- 			if M.debug.pkt then print("[I] PKT ",C2R[hdr.type],'#',hdr.seq,' + ',hdr.len) end
-- 			if self.req[ hdr.seq ] then
-- 				if type(self.req[ hdr.seq ]) ~= 'number' then
-- 					local res
-- 					if hdr.len >= 4 then
-- 						local code = hdr.code
-- 						if code == 0 then
-- 							-- ffi.string( self.rbuf + pkoft + 4, hdr.len-4 ))
-- 							if hdr.len >= 8 then
-- 								local tuples = {}
-- 								local data = ffi.cast("char *", self.rbuf + pkoft + 8)
-- 								local fin = data + (hdr.len - 8)
-- 								local res = (function()
-- 									local tuples = {}
-- 									for t = 0,hdr.count-1 do
-- 										print("tuple ", t)
-- 										if data >= fin then
-- 											return {8,"intersection"}
-- 										end
-- 										local tsize = ffi.cast('uint32_t *',data)[0]
-- 										local fcount = ffi.cast('uint32_t *',data + 4)[0]
-- 										print(tsize, fcount)
-- 										data = data + 8
-- 										if data + tsize > fin then
-- 											log.info("%s + %s - %s",data,tsize,fin)
-- 											return {8,"intersection of tuple"}
-- 										end
-- 										local row  = {}
-- 										for f = 0,fcount-1 do
-- 											local fsize = 0
-- 											while true do
-- 												print("fsize... ",fsize, bit.band(data[0],0x7f))
-- 												fsize = bit.bor(bit.lshift(fsize,7),
-- 													bit.band(data[0],0x7f))
-- 												if bit.band(data[0],0x80) == 0 or data > fin then break end
-- 												data = data + 1
-- 											end
-- 											data = data + 1
-- 											print("fsize = ",fsize)
-- 											print("field = ",ffi.string(data,fsize))
-- 											if data + fsize > fin then
-- 												return {8,"intersection of field"}
-- 											end
-- 											table.insert(row,ffi.string(data,fsize))
-- 											data = data + fsize
-- 										end
-- 										table.insert(tuples,row)
-- 									end
-- 									return {0,tuples}
-- 								end)()
-- 								print(dump(res))
-- 							else
-- 								-- have no count field in struct => no tuples (VERY LEGACY)
-- 								res = {0,{}}
-- 							end
-- 						else
-- 							res = { tonumber(code), ffi.string( self.rbuf + pkoft + 4, hdr.len-4 ) }
-- 						end
-- 					else
-- 						-- empty response. (OMG)
-- 						res = {0,{}}
-- 					end
-- 					self.req[ hdr.seq ]:put(res)
-- 				else
-- 					print("Received timed out ",C2R[ hdr.type ], "#",hdr.seq," after ",string.format( "%0.4fs", fiber.time() - self.req[ hdr.seq ] ))
-- 				end
-- 				self.req[ hdr.seq ] = nil
-- 			else
-- 				print("Got no requestor for ",hdr.seq)
-- 			end
-- 			pkoft = pkoft + hdr.len
-- 		else
-- 			if hdr.len + 12 > self.maxbuf then
-- 				self:_buffer_state()
-- 				print("[E] Received too big packet ",C2R[hdr.type],'#',hdr.seq,' + ', hdr.len,". Max avail: ",self.maxbuf)
-- 			end
-- 			break
-- 		end
-- 	end
-- 	self.avail = self.avail - pkoft
-- end

function M:_waitres( seq )
	local ch = fiber.channel(1)
	self.req[ seq ] = ch
	local now = fiber.time()
	local body = ch:get( self.timeout ) -- timeout?
	--print("got body = ",body, " ",self.lasterror)
	if body then
		if body[1] == 0 then
			return unpack(body[2])
		else
			self.ERROR = body[1]
			error(body[2],2)
		end
	elseif body == false then
		self.req[ seq ] = nil
		print("Request #",seq," error: "..self.lasterror.." after ",string.format( "%0.4fs", fiber.time() - now ))
		self.ERROR = nil
		error( "Request #"..seq.." error: "..self.lasterror, 2 )
	else
		self.req[ seq ] = now
		self.ERROR = nil
		error("Request #"..seq.." timed out after "..string.format( "%0.4fs", fiber.time() - now ),2)

	end

	-- body
end

function M:ping()
	local res,err = pcall(self.request, self, 65280,'')
	return res
end

function M:call(proc,...)
	local seq = self.seq()
	local count = select('#',...)
	local outsize = 12 + #proc + 5 + 4
	local fields = ffi.new('tnt_pkt_field_t[?]',count)
	for i = 1,count do
		local val = tostring(select(i,...))
		fields[i-1].len = #val
		fields[i-1].data = ffi.cast('char *',val)
		outsize = outsize + 5 + #val
	end
	tuple[0].count = count
	tuple[0].fields = fields
	local out = ffi.new('char[?]',outsize)
	sz_ptr[0] = ffi.sizeof(out)

	-- TODO: reusable big vector

	-- if outsize >= ffi.sizeof(fixbuf) then
	-- 	-- grow by 64b blocks or by 1/4 of data aligned by 64b
	-- 	local alg = math.ceil(outsize / 4 / 64) * 64
	-- 	local nsz = math.ceil(outsize / alg) * alg
	-- 	log.info("realloc buffer %d => %d",ffi.sizeof(fixbuf), nsz)
	-- 	fixbuf = ffi.new('char[?]',nsz)
	-- end
	-- local out = fixbuf
	-- sz_ptr[0] = ffi.sizeof(fixbuf)

	if not lib.tnt_call(out, sz_ptr, char_ptr, seq, 0, proc, #proc, tuple) then
		error("Failed to create packet: "..ffi.string(char_ptr[0]),2);
	end
	-- local str = ffi.string(out,sz_ptr[0])
	-- print(xd( str ))
	self:push_write(out,sz_ptr[0]);
	self:flush()
	return self:_waitres(seq)
end


-- function M:lua(proc,...)
-- 		--[[
-- 			return                        ()                               must be ()
-- 			return {{}}                   tuple()                          would be ''
-- 			return 123                    tuple({123})                     must be (123)
-- 			return {123}                  tuple({123})                     must be (123)
-- 			return {123,456}              tuple({123,456})                 must be (123,456)
			
-- 			return {{123}}                tuple({123})                     must be (123)
			
-- 			return 123,456                tuple({123}),tuple({456})        such return value prohibited. would be (123)
-- 			return {{123},{456}}          (tuple({123}), tuple({456}))     such return value prohibited. would be (123)
-- 		]]--
-- 	local cnt = select('#',...)
-- 	local r = 
-- 	{ self:request(22,
-- 		box.pack('iwaV',
-- 			0,                      -- flags
-- 			#proc,
-- 			proc,
-- 			cnt,
-- 			...
-- 		)
-- 	) }
-- 	if #r == 0 then return end
-- 	local t = r[1]:totable()
-- 	return (unpack( t ))
-- end
-- M.ecall = M.lua

--[[
function M:delete(space,...)
	local key_part_count = select('#', ...)
	local r = self:request(21,
		box.pack('iiV',
			space,
			box.flags.BOX_RETURN_TUPLE,  -- flags
			key_part_count, ...
		)
	)
	return r
end

function M:replace(space, ...)
	local field_count = select('#', ...)
	return self:request(13,
		box.pack('iiV',
			space,
			box.flags.BOX_RETURN_TUPLE,
			field_count, ...
		)
	)
end

function M:insert(space, ...)
	local field_count = select('#', ...)
	return self:request(13,
		box.pack('iiV',
			space,
			bit.bor(box.flags.BOX_RETURN_TUPLE,box.flags.BOX_ADD),
			field_count, ...
		)
	)
end

function M:update(space, key, format, ...)
	local op_count = select('#', ...)/2
	return self:request(19,
		box.pack('iiVi'..format,
			space,
			box.flags.BOX_RETURN_TUPLE,
			1, key,
			op_count, ...
		)
	)
end

function M:select( space, index, ...)
	return self:select_limit(space, index, 0, 0xffffffff, ...)
end

function M:select_limit(space, index, offset, limit, ...)
	local key_part_count = select('#', ...)
	return self:request(17,
		box.pack('iiiiiV',
			space,
			index,
			offset,
			limit,
			1, -- key count
			key_part_count, ...
		)
	)
end

function M:select_range( sno, ino, limit, ...)
	return self:call(
		'box.select_range',
		tostring(sno),
		tostring(ino),
		tostring(limit),
		...
	)
end

function M:select_reverse_range( sno, ino, limit, ...)
	return self:call(
		'box.select_reverse_range',
		tostring(sno),
		tostring(ino),
		tostring(limit),
		...
	)
end

]]

return M
