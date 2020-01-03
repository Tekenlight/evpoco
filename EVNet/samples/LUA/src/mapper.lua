function isempty(s)
	return s == nil or s == '';
end
function map_request_to_handler()
	local request_handler = "formserver.lua";
	local request_handler_func = "handle_request";
	local request = context.get_http_request();
	--local host = request:get_host();
	--local method = request:get_method();
	local uri = request:get_uri();
	--print('host',host);
	--print('method',method);
	--print('uri',uri);
	--print('Headers');
	--local headers = request:get_hdr_fields();
	--for k,v in pairs(headers) do
		--print(string.format('%s:%s', k, v));
	--end
	--local referer = request:get_hdr_field('Referer');
	--print('Referer:', referer);
	local url_parts = {};
	local i = 0;
	for w in (string.gmatch(uri, '(/[^/?]*)')) do
		i = i+1;
		url_parts[i] = string.sub(w, 2);
	end

	--print(table.unpack(url_parts));
	if (isempty(url_parts[1])) then url_parts[1] = 'default_handler.lua'; end
	if (isempty(url_parts[2])) then url_parts[1] = 'handle_request'; end
	return url_parts[1], url_parts[2];
end
