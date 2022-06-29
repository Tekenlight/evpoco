local ws = require('service_utils.WS.web_socket');
local ws_util = require('service_utils.WS.ws_util');
local ws_const = require('service_utils.WS.ws_const');
local ffi = require('ffi');
local error_handler = require("lua_schema.error_handler");


ffi.cdef[[
char * strcpy(char * dst, const char * src);
]]

local conn, status, hdrs = ws.connect({ url = "http://localhost:9982/registrar/wss_test",
										msg_handler = "biop.registrar.wsc_test",
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


local meta = ws_util.ping(conn);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
require 'pl.pretty'.dump(meta);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);

--local r_meta = ws_util.recv_frame(conn);
--print(debug.getinfo(1).source, debug.getinfo(1).currentline);
--require 'pl.pretty'.dump(r_meta);
--print(debug.getinfo(1).source, debug.getinfo(1).currentline);
--print(debug.getinfo(1).source, debug.getinfo(1).currentline, ffi.string(r_meta.buf));

print(debug.getinfo(1).source, debug.getinfo(1).currentline);
print("GETTING INTO OS SLEEP");
os.execute("sleep 5");
print("OS SLEEP IS OVER");
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
print("NOW GETTING INTO HIBERNATION");
--platform.ev_hibernate(220);
print("HIBERNATION IS OVER");
print(debug.getinfo(1).source, debug.getinfo(1).currentline);

--ws_util.close(conn);
--OR
platform.stop_taking_requests();
--platform.ev_hibernate(200);
platform.ev_hibernate(1);

--[[
local i = 0;
while (i < 100) do
	i = i + 1;
	platform.ev_hibernate(2);
	ws_util.ping(conn);
end
--]]

return;




