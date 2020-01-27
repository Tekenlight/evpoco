function handle_request()
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();
	response:set_chunked_trfencoding(true);
	response:set_content_type("text/plain");
	response:send();
	ev_sleep(2000000);
	local buf = request:read();
	response:write(buf);
	return ;
end

local arg = {...}
req_handler_func_name = arg[2];
local func = _G[req_handler_func_name];

return pcall(func);

