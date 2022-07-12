local ws = require('service_utils.WS.web_socket');
local ws_util = require('service_utils.WS.ws_util');
local ws_const = require('service_utils.WS.ws_const');
local ffi = require('ffi');
local error_handler = require("lua_schema.error_handler");

local cjson = require("cjson.safe");

local args = {...};

if (args[1] == nil) then
	error("no first argument");
end

local org_id = args[1];

local conn = ws_util.get_ws_from_pool(org_id);

local msg_s = {
	topic = "001",
	data = "NEW EVENTS AVAILABLE"
};
local json_parser = cjson.new();
local flg, json_str, err = pcall(json_parser.encode, msg_s);


while (true) do
	if (conn ~= nil) then
		ws_util.send_msg(conn, json_str);
	end
	platform.ev_hibernate(2);
	if (conn == nil) then
		conn = ws_util.get_ws_from_pool(org_id);
	end
end

