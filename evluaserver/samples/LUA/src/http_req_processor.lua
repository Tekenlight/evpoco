URI = require("uri");

function isempty(s)
	return s == nil or s == '';
end
function map_request_to_handler(request)
	local uri = request:get_uri();
	local url_parts = {};
	local i = 0;
	local j = 0;
	local first_url_char = uri:sub(1,1);

	local url_parts1 = URI:new(uri);
	for i,v in ipairs((require "pl.stringx".split(url_parts1:path(), '/'))) do
		if (i ~= 1) then
			url_parts[i-1] = v;
		end
	end
	if (isempty(url_parts[1])) then url_parts[1] = 'default_handler'; end
	if (isempty(url_parts[2])) then url_parts[2] = 'handle_request'; end
	--[[
	if (nil == string.find(url_parts[1], '.lua')) then
		local s = url_parts[1];
		url_parts[1] = s..'.lua';
	end
	--]]

	return url_parts[1], url_parts[2];
end


local evp = require("ev_postgres");
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
local conn = evp.open_connetion('127.0.0.1', '5432', 'AAA', 'gen', 'GEN');
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
conn:begin();


local stmt, msg = conn:prepare("SELECT BIOP_ADMIN.BIOP_USER_PROFILES.city, BIOP_ADMIN.BIOP_REF_CODES.ref_code from BIOP_ADMIN.BIOP_USER_PROFILES, BIOP_ADMIN.BIOP_REF_CODES WHERE BIOP_ADMIN.BIOP_USER_PROFILES.city = BIOP_ADMIN.BIOP_REF_CODES.ref_code and BIOP_ADMIN.BIOP_REF_CODES.ref_type = '01'");
local flg, msg = stmt:execute();
print(debug.getinfo(1).source, debug.getinfo(1).currentline, stmt);
local columns = stmt:columns();
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
require 'pl.pretty'.dump(columns);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
local flg, msg = stmt:execute();
print(debug.getinfo(1).source, debug.getinfo(1).currentline, flg, msg);
local stmt1, msg = conn:prepare("SELECT a.ref_code, a.ref_desc from BIOP_ADMIN.BIOP_REF_CODES a");
local flg, msg = stmt1:execute();
print(debug.getinfo(1).source, debug.getinfo(1).currentline, flg, msg);
local stmt2, msg = conn:prepare("SELECT ref_code from BIOP_ADMIN.BIOP_REF_CODES");
local flg, msg = stmt2:execute();
print(debug.getinfo(1).source, debug.getinfo(1).currentline, flg, msg);


conn:rollback();

local platform = require("platform");
local request = platform.get_http_request();
local response = platform.get_http_response();

local req_handler_name, func = map_request_to_handler(request);
local req_handler = require(req_handler_name);
return pcall(req_handler[func], request, response); 

