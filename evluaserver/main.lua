local error_msg_handler = function (msg) 
	local msg_line = msg;
	if (msg_line == nil) then msg_line = ''; end
	local parts_of_msg_line = require "pl.stringx".split(msg_line, ':');
	print (debug.traceback(msg, 3));
	print(debug.getinfo(1).source, debug.getinfo(1).currentline);
	require 'pl.pretty'.dump(parts_of_msg_line);
	print(debug.getinfo(1).source,     debug.getinfo(1).currentline);
	if (#parts_of_msg_line > 2) then
		local message = require "pl.stringx".strip(parts_of_msg_line[3]);
		local i = 4;
		while (i <= #parts_of_msg_line) do
			message = message ..":".. parts_of_msg_line[i];
			i = i + 1;
		end
	end
	print (debug.traceback(msg, 3));
	return msg;
end

local declaredNames = {}

function declare (name, initval)
	rawset(_G, name, initval)
	declaredNames[name] = true
end

function variable_declared(name)
	return (rawget(_G, name) ~= nil);
end

local exception_list = {
	___CACHED_FILE_EXISTS_FUNCTION___ = true,
	___CACHED_PATH_FUNCTION___ = true,
	___FILE_CACHING_FUNCTION___ = true,
	___ADDTO_CACHED_PATH_FUNCTION___ = true,
	unpack = true,
	warn = true,
	message_validation_context = true,
	element_handler_cache = true,
	bigdecimal_init = true,
}

local function in_exception_list(n)
	return (exception_list[n] ~= nil);
end

setmetatable(_G, {
	__newindex = function (t, n, v)
		if (in_exception_list(n)) then
			return rawset(t, n, v);
		end
		if not declaredNames[n] then
			print(debug.traceback("attempt to write to undeclared var. "..n, 3));
			--return rawset(t, n, v);
			error("attempt to write to undeclared var. "..n, 2)
		else
			rawset(t, n, v)   -- do the actual set
		end
	end,
	__index = function (_, n)
		if (in_exception_list(n)) then
			return rawget(_, n);
		end
		if not declaredNames[n] then
			print(debug.traceback("attempt to read undeclared var. "..n, 3));
			--return rawget(_, n);
			error("attempt to read undeclared var. "..n, 2)
		else
			print(debug.traceback("attempt to read undeclared var. "..n, 3));
			return nil
		end
	end,
})




local error_handler = require("lua_schema.error_handler");
local platform = require("platform");
local request = platform.get_http_request();
local response = platform.get_http_response();

local supported_http_methods = { GET = 1, PUT = 1, POST = 1, DELETE = 1 };
local method = request:get_method();
if (method == 'OPTIONS') then
	response:set_hdr_field("Access-Control-Allow-Origin", "*");
	response:set_hdr_field("Access-Control-Allow-Methods", "OPTIONS, GET, PUT, POST, DELETE");
	response:set_hdr_field("Access-Control-Allow-Headers", "*");
	response:set_hdr_field("Access-Control-Allow-Credentials", "true");
	response:set_hdr_field("Access-Control-Max-Age", "360000");
	response:set_chunked_trfencoding(true);
	response:set_keep_alive(true);
	--response:set_hdr_field("Connection", "Keep-Alive");
	response:send();
	--response:write('\r\n');
	collectgarbage();
	return true;
end

response:set_hdr_field("Access-Control-Allow-Origin", "*");
response:set_hdr_field("Access-Control-Allow-Methods", "OPTIONS, GET, PUT, POST, DELETE");
response:set_hdr_field("Access-Control-Allow-Headers", "*");
response:set_hdr_field("Access-Control-Allow-Credentials", "true");

local status, req_handler = xpcall(require, error_msg_handler, 'service_utils.REST.controller');
if (not status) then
	error(req_handler);
end

local status, msg =  xpcall(req_handler['handle_request'], error_msg_handler, request, response); 
if (not status) then
	local out_obj = { error_message = msg }

	if (EVR_MODE == 0) then
		local status = 500;
		--[[ 500, since this situation has arised out of any unhandled errors in
		--handle_reauest
		--]]
		local cjson = require('cjson.safe');
		local json_parser = cjson.new();
		local flg, json_output, err = pcall(json_parser.encode, out_obj);

		response:set_status(status);
		response:set_chunked_trfencoding(true);
		response:set_content_type("application/json");
		response:set_hdr_field("X-msg", json_output);
		response:send();
		response:write(json_output);
	else
		print(debug.getinfo(1).source, debug.getinfo(1).currentline);
		require 'pl.pretty'.dump(out_obj);
		print(debug.getinfo(1).source, debug.getinfo(1).currentline);
	end
end

collectgarbage();
collectgarbage();

return status;

