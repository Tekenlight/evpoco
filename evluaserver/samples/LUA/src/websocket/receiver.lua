local ws = require('service_utils.WS.web_socket');
local ws_util = require('service_utils.WS.ws_util');
local ws_const = require('service_utils.WS.ws_const');
local ffi = require('ffi');
local error_handler = require("lua_schema.error_handler");
local cjson = require('cjson.safe');


ffi.cdef[[
char * strcpy(char * dst, const char * src);
]]

local auth =  [[Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBQUEtU2VydmljZSIsInVpZCI6IjgiLCJuYmYiOjE2NDA0MDA2MjYsImxvZ2dlZF9pbl9hcyI6InN1ZGhlZXIuaHJAdGVrZW5saWdodC5jb20iLCJleHAiOjE5NTU3NjA2MjYsImp0aSI6IjEwOSJ9.tDYdFLJGiUC2scbw-KlT74HIZg4PkezBFRKlikphpnw]]
local x_auth = [[eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBQUEtU2VydmljZSIsInVpZCI6IjgiLCJuYmYiOjE2NDA0MDA2MjYsImxvZ2dlZF9pbl9hcyI6InN1ZGhlZXIuaHJAdGVrZW5saWdodC5jb20iLCJleHAiOjE5NTU3NjA2MjYsImp0aSI6IjEwOSJ9.tDYdFLJGiUC2scbw-KlT74HIZg4PkezBFRKlikphpnw]]

--[=[
local conn, status, hdrs = ws.connect({ url = "http://localhost:9982/registrar/wss_test",
										msg_handler = "biop.registrar.wsc_test",
										hdrs = {
											Authorization =  [[Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBQUEtU2VydmljZSIsInVpZCI6IjgiLCJuYmYiOjE2NDA0MDA2MjYsImxvZ2dlZF9pbl9hcyI6InN1ZGhlZXIuaHJAdGVrZW5saWdodC5jb20iLCJleHAiOjE5NTU3NjA2MjYsImp0aSI6IjEwOSJ9.tDYdFLJGiUC2scbw-KlT74HIZg4PkezBFRKlikphpnw]],
											["X-Auth"] = [[eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBQUEtU2VydmljZSIsInVpZCI6IjgiLCJuYmYiOjE2NDA0MDA2MjYsImxvZ2dlZF9pbl9hcyI6InN1ZGhlZXIuaHJAdGVrZW5saWdodC5jb20iLCJleHAiOjE5NTU3NjA2MjYsImp0aSI6IjEwOSJ9.tDYdFLJGiUC2scbw-KlT74HIZg4PkezBFRKlikphpnw]]
										}
									} );
									--]=]
local conn, status, hdrs = ws.connect({ url = "http://localhost:9982/registrar/wss_test",
										msg_handler = "biop.registrar.wsc_test",
										hdrs = {
											Authorization =  auth,
											["X-Auth"] = x_auth
										}
									} );
if (conn == nil)  then
	print(status);
	return;
end

local message_obj = {
	command = "SUBSCRIPTION",
	topic = "001"
}


local json_parser = cjson.new();
local flg, json_str, err = pcall(json_parser.encode, message_obj);

local meta = ws_util.send_msg(conn, json_str);
print(ffi.string(meta.buf));

while (1) do
	platform.ev_hibernate(4)
	local status = pcall(ws_util.ping, conn, "KEEP ALIVE");
	if (not status) then
		print("MAUSAM KHARAB HONE KE KARAN, PRASAR ME ADACHAN HEI");
		print("RUKAWAT KE LIYE KHED HEI");
		local status, stat1, hdrs;
		status, conn, stat1, hdrs = pcall(ws.connect, { url = "http://localhost:9982/registrar/wss_test",
												msg_handler = "biop.registrar.wsc_test",
												hdrs = { Authorization =  auth, ["X-Auth"] = x_auth } } );
		--print(status)
		--print(debug.getinfo(1).source, debug.getinfo(1).currentline);
		--require 'pl.pretty'.dump(conn);
		--print(debug.getinfo(1).source, debug.getinfo(1).currentline);
		local stat2, meta = pcall(ws_util.send_msg, conn, json_str);
		--print(stat2)
	end
end


ws_util.close(conn);
platform.ev_hibernate(1);


return;




