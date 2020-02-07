local handlers = {};
handlers.handle_request = function () -- {
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();

	local srl_num1 = platform.nb_make_http_connection('localhost', 9980);
	local srl_num2 = platform.nb_make_http_connection('localhost', 9980);

	local fh, err = platform.file_open("./Sudheer.JPG", "r");
	--local fh1, err1 = platform.file_open("./cha.JPG", "w+");
	if (err ~= nil) then error(err); end
	if (err1 ~= nil) then error(err1); end

	local http_request_factory = require('http_request_factory'); 

	local echo_request1 = http_request_factory:new();
	echo_request1:set_uri('http://localhost:9980/echoserver.lua/handle_request');
	echo_request1:set_method('GET');
	echo_request1:set_host('localhost:9980');
	local s = 'this is a random request body';
	echo_request1:set_content_length(string.len(s));
	--echo_request1:set_expect_continue(true); 

	local echo_request2 = http_request_factory:new();
	echo_request2:set_uri('http://localhost:9980/echoserver.lua/handle_request');
	echo_request2:set_method('GET');
	echo_request2:set_host('localhost:9980');
	local s = 'this is a random request body';
	echo_request2:set_content_length(string.len(s));
	--echo_request2:set_expect_continue(true); 

	local compl = platform.wait();
	local conn1, err = platform.task_return_value(compl);
	platform.send_request_header(conn1, echo_request1);
	echo_request1:write(s);
	platform.send_request_body(conn1, echo_request1);

	compl = platform.wait();
	local conn2, err1 = platform.task_return_value(compl);
	print(ev_getmtname(conn2))
	platform.send_request_header(conn2, echo_request2);
	echo_request2:write(s);
	platform.send_request_body(conn2, echo_request2);

	local s1 = platform.nb_receive_http_response(conn1);
	local s2 = platform.nb_receive_http_response(conn2);
	--local echo_response1 = platform.receive_http_response(conn1);
	--local echo_response2 = platform.receive_http_response(conn2);

	local _1 = platform.wait();
	local echo_response1, err = platform.task_return_value(_1);
	local buf1 = echo_response1:read();
	print(buf1);

	local _2 = platform.wait();
	local echo_response2, err = platform.task_return_value(_2);
	local buf2 = echo_response2:read();
	print(buf2);

	if (err ~= nil) then error(err); end
	if (err1 ~= nil) then error(err1); end
	local i = 0;
	local buffer = platform.alloc_buffer(4096);
	local n, msg = fh:read_binary(buffer, 4096);
	response:set_chunked_trfencoding(true);
	response:set_content_type("image/jpeg");
	response:send();
	local ret = 0;
	while (n ~= 0) do -- {
		i = i + 1;
		if (i == 1) then --{
			--print('hhhhhh');
			--print(n..' +');
			--ret = fh1:write_binary(buffer, n);
			response:write(buffer, n);
		end -- }
		--print('hihihihi');
		if (n == -1) then -- {
			print(msg);
			break;
		end -- }
		n, msg = fh:read_binary(buffer, 4096);
		--print('chachi');
		--print(n..' +');
		--ret = fh1:write_binary(buffer, n);
		response:write(buffer, n);
	end -- }
	fh:close();
	--fh1:close();

	return ;
end -- }

local arg = {...}
req_handler_func_name = arg[2];
local func = handlers[req_handler_func_name];

return pcall(func);

