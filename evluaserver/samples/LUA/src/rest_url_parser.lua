local funcs = {}

funcs.parse_url_path = function (request) -- {
	local uri = request:get_uri();
	local url_parts = {};
	local i = 0;
	local j = 0;
	local first_url_char = uri:sub(1,1);
	for w in (string.gmatch(uri, '(/[^/?]*)')) do
		i = i+1;
		if (first_url_char ~= "/") then
			-- Ignore the first 3 url parts
			-- http://....../...
			if (i>=3) then
				j=j+1;
				--print(w);
				local s = string.sub(w, 2);
				url_parts[j] = string.sub(w, 2);
			end
		else
			-- It is ony a path
			j=j+1;
			local s = string.sub(w, 2);
			url_parts[j] = string.sub(w, 2);
		end
	end

	return j, url_parts;
end -- }

funcs.get_qry_params = function (request) -- {
	local qp=request:get_query_parameters();
	return qp;
end -- }

return funcs;

