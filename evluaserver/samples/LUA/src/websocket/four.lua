local ws = require('service_utils.WS.web_socket');
local ws_util = require('service_utils.WS.ws_util');
local ws_const = require('service_utils.WS.ws_const');
local ffi = require('ffi');
local error_handler = require("lua_schema.error_handler");


ffi.cdef[[
char * strcpy(char * dst, const char * src);
]]

local conn, status, hdrs = ws.connect({ url = "http://localhost:9982/registrar/wss_test",
										hdrs = {
											Authorization =  [[Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBQUEtU2VydmljZSIsInVpZCI6IjgiLCJuYmYiOjE2NDA0MDA2MjYsImxvZ2dlZF9pbl9hcyI6InN1ZGhlZXIuaHJAdGVrZW5saWdodC5jb20iLCJleHAiOjE5NTU3NjA2MjYsImp0aSI6IjEwOSJ9.tDYdFLJGiUC2scbw-KlT74HIZg4PkezBFRKlikphpnw]],
											["X-Auth"] = [[eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBQUEtU2VydmljZSIsInVpZCI6IjgiLCJuYmYiOjE2NDA0MDA2MjYsImxvZ2dlZF9pbl9hcyI6InN1ZGhlZXIuaHJAdGVrZW5saWdodC5jb20iLCJleHAiOjE5NTU3NjA2MjYsImp0aSI6IjEwOSJ9.tDYdFLJGiUC2scbw-KlT74HIZg4PkezBFRKlikphpnw]]
										}
											} );
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
if (conn == ni) then
	print(status);
	return;
end
print(status, type(status));
require 'pl.pretty'.dump(hdrs);
require 'pl.pretty'.dump(conn);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);


local buffer = {};
buffer.size = 0;
buffer.index = 0;
--local file = io.open("/Volumes/NEW_DISK/user/sudheerp/platform/evpoco/evnet/src/EVTCPServer.cpp", "r");
--local file = io.open("/Volumes/NEW_DISK/user/sudheerp/platform/evpoco/evnet/include/Poco/evnet/EVTCPServer.h", "r");
--local str = file:read("a");
--local str = "Hello world\n";
local str = "PING"
print(debug.getinfo(1).source, debug.getinfo(1).currentline, string.len(str));
buffer.buf = ffi.new("unsigned char[?]", string.len(str));
buffer.size = string.len(str);
ffi.C.strcpy(buffer.buf, str);

local meta = ws_util.send_frame({ss = conn._ss, size = buffer.size, flags = ws_const.FRAME_OP_PING, buf = buffer.buf, use_mask = true});
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
require 'pl.pretty'.dump(meta);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);

local r_meta = ws_util.recv_frame(conn);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
require 'pl.pretty'.dump(r_meta);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
print(debug.getinfo(1).source, debug.getinfo(1).currentline, ffi.string(r_meta.buf));

print(debug.getinfo(1).source, debug.getinfo(1).currentline);
platform.ev_hibernate(5);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);

return;




