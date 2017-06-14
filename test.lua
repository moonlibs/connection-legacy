-- package.path = package.path .. ';../libs/share/lua/5.1/?/init.lua;../libs/share/lua/5.1/?.lua;'

box.cfg {
	background = false;
	logger_nonblock = true;
	read_only = true;
	wal_mode = 'none';
}

local ffi = require 'ffi'
local fiber = require 'fiber'

local function dump(x)
	local j = require'json'.new()
	j.cfg{
		encode_use_tostring = true;
	}
	return j.encode(x)
end


-- print(ffi.C.TNT_UPDATE_INSERT)

local tnt = require 'connection.legacy'
-- tnt.debug.rbuf = true
tnt.debug.pkt = true

print(tnt)
local cn = tnt("localhost",33013,{})

fiber.create(function()
	print("preparing to connect", cn)
	local ch = fiber.channel(1)

	cn.on_connected = function(self,...)
		print("connected", ...)
		print(cn)
		ch:put(false)
	end
	cn.on_connfail = function(self,...)
		print("connfail", ...)
	end
	cn.on_disconnect = function(self,...)
		print("disconnected", ...)
	end
	cn:connect()
	-- print(cn)
	ch:get()

	print("go on,", cn)


	fiber.create(function()
		print(dump{ cn:call("box.dostring", "return box.tuple.new({'a','b','c'}),box.tuple.new({'x','y'})") })
	end)
	fiber.create(function()
		print(dump{ cn:call("box.dostring", "return string.rep('x',129)") })
	end)

	if true then return end

	fiber.create(function()
		print(cn:call("box.dostring", "box.fiber.sleep(0.4); return 'delayed'"))
	end)

	for i=1,3 do
		fiber.create(function(ix)
			print(cn:call("box.dostring", "return 'test "..ix.."', 'xxx';"))
		end,i)
	end


	print(cn:call("call.my.legacy", "some",3,"args"))

end)


if true then return true end
