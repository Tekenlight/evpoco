function handle_request()
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();

	response:set_chunked_trfencoding(true);
	response:set_content_type("text/html");
	response:send();

	local http_request_factory = require('http_request_factory'); 
	local echo_request = http_request_factory:new();

	print('ECHO Server processing request');
	echo_request:set_uri('http://localhost:9980/echoserver.lua/handle_request');
	echo_request:set_method('GET');
	echo_request:set_host('localhost:9980');
	local s = 'this is a random request body';
	echo_request:set_content_length(string.len(s));
	echo_request:set_expect_continue(true); 
	local client_session, msg = platform.make_http_connection('localhost', 9980);
	platform.send_request_header(client_session, echo_request);

	echo_request:write(s);
	platform.send_request_body(client_session, echo_request);
	local echo_response = platform.receive_http_response(client_session);

	--for n,v in pairs(request:get_cookies()) do
		--print(n, v);
	--end
	--local c = request:get_hdr_field('Cookie');
	--print (c);

	response:write('<html>\n');
	response:write('<head>\n');
	response:write('<title>EVLUA Form Server Sample</title>\n');
	response:write('</head>\n');
	response:write('<body>\n');
	response:write('<h1>EVLUA Form Server Sample</h1>\n');
	response:write('<h2>GET Form</h2>\n');
	response:write('<form method=\"GET\" action=\"/orchserver.lua/handle_request\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"GET\">\n');
	response:write('</form>\n');
	response:write('<h2>POST Form</h2>\n');
	response:write('<form method=\"POST\" action=\"/orchserver.lua/handle_request\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"POST\">\n');
	response:write('</form>\n');
	response:write('<h2>File Upload</h2>\n');
	response:write('<form method=\"POST\" action=\"/orchserver.lua/handle_request\" enctype=\"multipart/form-data\">\n');
	response:write('<input type=\"file\" name=\"file\" size=\"31\"> \n');
	response:write('<input type=\"submit\" value=\"Upload\">\n');
	response:write('</form>\n');
	response:write('<h2>Request</h2><p>\n');
	response:write('Method: '..request:get_method());
	response:write('<br>\n');
	response:write('URI: '..request:get_uri());
	response:write('<br>\n');

	local headers = request:get_hdr_fields();
	for k,v in pairs(headers) do
		response:write(string.format('%s : %s<br>\n', k, v));
	end
	response:write('</p>\n');

	if (false == form:empty()) then
		response:write('<h2>Form</h2><p>\n');
		it, k, v = form:begin_iteration();
		while (k ~= nil) do
			response:write(k..': '..v..'<br>\n');
			k, v = form:next_iteration(it);
		end
		response:write('</p>');
	end
	local parts = request:get_part_names();
	for _, p in ipairs(parts) do
		local part = request:get_part(p);
		response:write('<h2>Upload</h2><p>\n');
		response:write('Name: '..part['name']..'<br>\n');
		response:write('File Name: '..p..'<br>\n');
		response:write('Type: '..part['type']..'<br>\n');
		response:write('Size: '..part['length']..'<br>\n');
		response:write('<br>\n');
	end
	response:write('</p>');

	local buf = echo_response:read();

	response:write('<p>');
	response:write('<h3>Received data from upstream server</h3>\n');
	response:write(buf);
	response:write('\n');
	response:write('</p>');

	response:write('</body>\n');

	return ;
end

local arg = {...}
req_handler_func_name = arg[2];
local func = _G[req_handler_func_name];

return pcall(func);

