local handlers = {};
handlers.handle_request = function () -- {
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();

	local srl_num1 = platform.make_http_connection_nb('localhost', 9980);
	local srl_num2 = platform.make_http_connection_nb('localhost', 9980);
	local srl_num = 1;
	print(srl_num1);
	print(srl_num2);

	local fh, err = platform.file_open("./Sudheer.JPG", "r");
	local fh1, err1 = platform.file_open("./cha.JPG", "w+");

	--local compl = platform.wait({srl_num1, srl_num2});
	local compl = platform.wait();
	print(compl);
	compl = platform.wait();
	print(compl);
	--local fh, err = platform.file_open("./Sudheer.JPG", "r");
	--local fh, err = platform.file_open("/etc/krb5.keytab", "r");
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
			ret = fh1:write_binary(buffer, n);
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
		ret = fh1:write_binary(buffer, n);
		response:write(buffer, n);
	end -- }
	fh:close();
	fh1:close();

	return ;
end -- }

local arg = {...}
req_handler_func_name = arg[2];
local func = handlers[req_handler_func_name];

return pcall(func);

