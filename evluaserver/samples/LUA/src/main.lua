local error_handler = require("lua_schema.error_handler");
local platform = require("platform");
local socket_upgraded = platform.get_socket_upgrade_to();
local request = platform.get_http_request();
local response = platform.get_http_response();

response:set_hdr_field("Access-Control-Allow-Origin", "*");
response:set_hdr_field("Access-Control-Allow-Methods", "*");
response:set_hdr_field("Access-Control-Allow-Headers", "*");
response:set_hdr_field("Access-Control-Allow-Credentials", "true");


local status, req_handler = pcall(require, 'service_utils.REST.controller');
if (not status) then
	error(req_handler);
end
local status, msg =  pcall(req_handler['handle_request'], request, response); 

if (not status) then
	error(msg);
end

collectgarbage();

return status;

