local handlers = {};
handlers.handle_request = function () -- {
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();
	response:set_chunked_trfencoding(true);
	response:set_content_type("video/mp4");
	response:send();

	local fh, err = platform.file_open("./SatisfiabilityAndCookTheorem.mp4", "r");
	--local fh, err = platform.file_open("./Sudheer.JPG", "r");
	--local fh, err = platform.file_open("/etc/krb5.keytab", "r");
	if (err ~= nil) then error(err); end
	if (err1 ~= nil) then error(err1); end
	local i = 0;
	local j = 0;
	local buffer = platform.alloc_buffer(1048576);
	--print('This is before read prior to the loop');
	local n, msg = fh:read_binary(buffer, 1048576);
	local ret = 0;
	while (n ~= 0) do -- {
		i = i + 1;
		j = j + 1;
		if (i == 1) then --{
			--print('hhhhhh');
			--print(n..' +');
			response:write(buffer, n);
		end -- }
		--print('hihihihi');
		if (n == -1) then -- {
			print(msg);
			break;
		end -- }
		--print('This is before read in the loop');
		n, msg = fh:read_binary(buffer, 1048576);
		--print('chachi');
		--print(n..' +');
		if (j == 1000) then -- {
			print("1000 packets sent");
			j = 0;
		end -- }
		response:write(buffer, n);
	end -- }
	fh:close();


	return ;
end -- }

local arg = {...}
req_handler_func_name = arg[2];
local func = handlers[req_handler_func_name];

return pcall(func);

