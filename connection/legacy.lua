local obj = require 'obj'
local connection = require 'connection'
local ffi = require 'ffi'

if not pcall(ffi.typeof,"tnt_hdr_t") then
	ffi.cdef[[
		typedef struct {
			uint32_t pkt;
			uint32_t len;
			uint32_t seq;
		} tnt_hdr_t;
	]]
end
local tnt_hdr_t = ffi.typeof('tnt_hdr_t')

local M = obj.class({ debug = {} },'connection.legacy',connection)

local C2R = {
	[65280] = 'ping',
	[13]    = 'insert',
	[17]    = 'select',
	[19]    = 'update',
	[21]    = 'delete',
	[22]    = 'call',
}

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
		print("[I] BUF[", self.avail, ']: ', C2R[hdr.pkt],'#',hdr.seq,' + ', ( tonumber(self.avail) - 12 ), ' of ' , hdr.len)
	elseif self.avail >= 8 then
		local hdr = ffi.cast('tnt_hdr_t *',self.rbuf)
		print("[I] BUF[", self.avail, ']: ', C2R[hdr.pkt],'#? + ',tonumber(self.avail) - 12, ' of ' , hdr.len)
	elseif self.avail >= 4 then
		local hdr = ffi.cast('tnt_hdr_t *',self.rbuf)
		print("[I] BUF[", self.avail, ']: ', C2R[hdr.pkt],'#? + ?')
	else
		print("[I] BUF[", self.avail,']')
	end
end

function M:on_read_(is_last)
	local pkoft = 0
	local avail = self.avail
	-- print("on_read ",self.avail)
	if M.debug.rbuf then self:_buffer_state() end
	while self.avail - pkoft >= 12 do
		local hdr = ffi.cast('tnt_hdr_t *',self.rbuf + pkoft)
		if self.avail - pkoft >= 12 + hdr.len then
			pkoft = pkoft + 12
			if M.debug.pkt then print("[I] PKT ",C2R[hdr.pkt],'#',hdr.seq,' + ',hdr.len) end
			if self.req[ hdr.seq ] then
				if type(self.req[ hdr.seq ]) ~= 'number' then
					--print("Have requestor for ",seq)
					-- if hdr.len > 0 then
						-- local body = ffi.string( self.rbuf + pkoft, hdr.len )
						-- print("body = ",body, " len = ",#body, " ", body:xd())
						-- self.req[ hdr.seq ]:put( ffi.string( self.rbuf + pkoft, hdr.len ) )

						-- self.req[ hdr.seq ]:put( { ffi.cast( 'char *', self.rbuf + pkoft ), hdr.len } )

						local res
						if hdr.len >= 4 then
							local code = ffi.cast('uint32_t *', self.rbuf + pkoft )[0]
							if code == 0 then
								res = { 0, { box.unpack('R', ffi.string( self.rbuf + pkoft + 4, hdr.len-4 )) } }
							else
								res = { tonumber(code), ffi.string( self.rbuf + pkoft + 4, hdr.len-4 ) }
							end
						else
							res = { 0, {''} }
						end
						self.req[ hdr.seq ]:put(res)

					-- else
						-- self.req[ hdr.seq ]:put( '' )
					-- end
					self.req[ hdr.seq ] = nil
				else
					print("Received timed out ",C2R[ hdr.pkt ], "#",hdr.seq," after ",string.format( "%0.4fs", box.time() - self.req[ hdr.seq ] ))
					self.req[ hdr.seq ] = nil
				end
			else
				print("Got no requestor for ",hdr.seq)
			end
			pkoft = pkoft + hdr.len
		else
			if hdr.len + 12 > self.maxbuf then
				self:_buffer_state()
				print("[E] Received too big packet ",C2R[hdr.pkt],'#',hdr.seq,' + ', hdr.len,". Max avail: ",self.maxbuf)
			end
			break
		end
	end
	-- print("avail = ",avail, " pkoft = ", pkoft)	while true do
	self.avail = self.avail - pkoft
end

function M:request(pktt,body)
	local seq = self.seq()
	local req = box.pack('iiia', pktt, #body, seq, body)
	-- print("request ",C2R[pktt] or pktt, "#", seq)
	self:write(req)
	local ch = box.ipc.channel(1)
	self.req[ seq ] = ch
	local now = box.time()
	local body = ch:get( self.timeout ) -- timeout?
	--print("got body = ",body, " ",self.lasterror)
	if body then
		if body[1] == 0 then
			return unpack(body[2])
		else
			box.raise(body[1], body[2])
		end
	elseif body == false then
		self.req[ seq ] = nil
		print("Request ",C2R[ pktt ], "#",seq," error: "..self.lasterror.." after ",string.format( "%0.4fs", box.time() - now ))
		box.raise( box.error.ER_PROC_LUA, "Request "..C2R[ pktt ].."#"..seq.." error: "..self.lasterror )
	else
		self.req[ seq ] = now
		print("Request ",C2R[ pktt ], "#",seq," timed out after ",string.format( "%0.4fs", box.time() - now ))
		box.raise( box.error.ER_PROC_LUA, "Request "..C2R[ pktt ].."#"..seq.." timed out" )
	end
end

function M:_waitres( seq )
	local ch = box.ipc.channel(1)
	self.req[ seq ] = ch
	local now = box.time()
	local body = ch:get( self.timeout ) -- timeout?
	--print("got body = ",body, " ",self.lasterror)
	if body then
		if body[1] == 0 then
			return unpack(body[2])
		else
			box.raise(body[1], body[2])
		end
		-- if body[2] > 0 then
		-- 	local code = ffi.cast('uint32_t *',body[1])[0]
		-- 	if code == 0 then
		-- 		return box.unpack('R',ffi.string( body[1]+4,body[2]-4 ))
		-- 	else
		-- 		box.raise(tonumber(code), ffi.string( body[1]+4,body[2]-4 ))
		-- 	end
		-- else
		-- 	return ''
		-- end
	elseif body == false then
		self.req[ seq ] = nil
		print("Request #",seq," error: "..self.lasterror.." after ",string.format( "%0.4fs", box.time() - now ))
		box.raise( box.error.ER_PROC_LUA, "Request #"..seq.." error: "..self.lasterror )
	else
		self.req[ seq ] = now
		print("Request #",seq," timed out after ",string.format( "%0.4fs", box.time() - now ))
		box.raise( box.error.ER_PROC_LUA, "Request #"..seq.." timed out" )
	end

	-- body
end

function M:ping()
	local res,err = pcall(self.request, self, 65280,'')
	return res
end

function M:call_old ( proc,... )
	local cnt = select('#',...)
	return self:request(22,
		box.pack('iwaV',
			0, -- flags
			#proc,
			proc,
			cnt,
			...
		)
	)
end

function M:call(proc,...)
	local cnt = select('#',...)
	local seq = self.seq()
	-- print("do call ",proc," ",seq," to "..self.host..':'..self.port)
	local body = box.pack('iwaV',
		0, -- flags
		#proc,
		proc,
		cnt,
		...
	)
	self:push_write(tnt_hdr_t(22,#body,seq),12)
	self:push_write(body)
	self:flush()
	--local ret = { self:_waitres(seq) }
	--print("got response for ",seq)
	--return unpack(ret)
	return self:_waitres(seq)
end


function M:lua(proc,...)
		--[[
			return                        ()                               must be ()
			return {{}}                   tuple()                          would be ''
			return 123                    tuple({123})                     must be (123)
			return {123}                  tuple({123})                     must be (123)
			return {123,456}              tuple({123,456})                 must be (123,456)
			
			return {{123}}                tuple({123})                     must be (123)
			
			return 123,456                tuple({123}),tuple({456})        such return value prohibited. would be (123)
			return {{123},{456}}          (tuple({123}), tuple({456}))     such return value prohibited. would be (123)
		]]--
	local cnt = select('#',...)
	local r = 
	{ self:request(22,
		box.pack('iwaV',
			0,                      -- flags
			#proc,
			proc,
			cnt,
			...
		)
	) }
	if #r == 0 then return end
	local t = r[1]:totable()
	return (unpack( t ))
end
M.ecall = M.lua

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