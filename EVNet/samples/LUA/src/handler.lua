function handle_request()
	return_string = 'Hello from LUA handler';
	ev_yield();
	local request = context.get_http_request();
	local form = request:parse_req_form();
	local it, k, v = form:begin_iteration();
	while (k ~= nil) do
		--print(it, k, v);
		k, v = form:next_iteration(it);
	end
	local parts = request:get_part_names();
	for _,v in ipairs(parts) do
		print(v);
		local p = request:get_part(v)
		for __, w in pairs(p) do
			print(__,w);
		end
		print('');
		print('PARAMS');
		print('------');
		local q = p['params']
		for __, w in pairs(q) do
			print(__,w);
		end
	end
	return return_string;
end
