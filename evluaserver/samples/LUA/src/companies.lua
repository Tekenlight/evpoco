local url_parts = {...}
urlp = require('rest_url_parser');
cjson = require('cjson.safe');
mongo = require('mongo');
roc_params = require('roc_db_param');
mcm = require('mongo_connection_manager');

local handlers = {};

--{
local function get_criteria_json_str(fields, query_params)
	local criteria = {};

	for _, f in ipairs(fields) do -- {
		if (query_params[f] ~= nil) then -- {
			criteria[f] = query_params[f];
		end -- }
	end -- }

	local i = 0;
	local crit_str = '';
	for field, value in pairs(criteria) do -- {
		i = i + 1;
		if (i>1) then -- {
			crit_str = crit_str..', ';
		end -- }
		crit_str = crit_str..'{ '..'"data.'..field..'" : { "$regex" : "'..value..'", "$options" :  "i" } }'
	end -- }
	if (i > 1) then -- {
		crit_str = '{ "$and" : [ '..crit_str..' ] }';
	elseif (i == 0) then -- } {
		crit_str = '{}'
	end -- }

	return mongo.BSON(crit_str);
end
--}

-- {
local function get_criteria(fields, query_params)
	local criteria = {};

	for _, f in ipairs(fields) do -- {
		if (query_params[f] ~= nil) then -- {
			criteria[f] = query_params[f];
		end -- }
	end -- }

	local i = 0;
	local crit_array = {__array=true}
	for field, value in pairs(criteria) do -- {
		local _crit_str = mongo.BSON{};
		local _field = 'data.'..field;
		local _value = mongo.Regex(value, "i");
		_crit_str:append(_field , _value)
		i = i + 1;
		crit_array[i] = _crit_str;
	end -- }

	local crit;
	if (i>1) then -- {
		local ab = {};
		ab["$and"] = crit_array;
		crit = mongo.BSON(ab);
	elseif (i==1) then -- } {
		crit = crit_array[1];
	end --}

	return crit;
end
-- }

-- {
handlers.list= function (query_params)
	local fields = {"org_id", "org_name"};
	local db_handle = mcm.connect(roc_params.db_url, roc_params.db_schema_name, roc_params.db_user_id, roc_params.db_user_password);
	local collection = db_handle:getCollection('companies');
	local criteria = get_criteria(fields, query_params);
	local cursor = collection:find(criteria);
	local result = {};
	local i = 0;
	local err = nil;
	for doc in cursor:iterator() do -- {
		i = i + 1;
		local record = {};
		for name,value in pairs(doc.data) do -- {
			if (type(value) == 'userdata') then -- {
				record[name] = tostring(value);
			else --} {
				record[name] = value;
			end -- }
		end -- }
		result[i] = record;
	end -- }
	return result, err;
end
-- }

-- {
handlers.add= function (query_params, company)
	return;
end
-- }

-- {
handlers.modify= function (query_params, company)
	return;
end
-- }

handlers.fetch= function (query_params) -- {
	return;
end -- }

handlers.delete= function (query_params, company)
-- {
	return;
end
-- }

--[[
--URL Standard followed in all BIOP API
--/Resource_name/<id>/<<verb>>
--Resource_name: Name of the set on which action is being performed
--<id>: Optional, if the action is being performed on a single entry in the set
--      id has to be supplied
--<<verb>>: Optional, can be supplied only if <id> is present
--          => 2nd parameter if present is always id
--          => 3rd parameter if present is always a verb, acting on the entry in the set
--             identified by <id>
--]]
-- {
local function deduce_class_function(request, num, url_parts, qp)
	local method = request:get_method();
	if (num == 1) then -- {
		if (method ~= 'GET') then -- {
			return nil, 'HTTP method '..method..' not supported'
		else --} {
			return 'list', nil;
		end -- }
	elseif (num == 2) then --} {
		if (method == 'GET') then --{
			return 'fetch', nil;
		elseif (method == 'PUT') then --} {
			return 'modify', nil;
		elseif (method == 'POST') then --} {
			return 'add', nil;
		elseif (method == 'DELETE') then --} {
			return 'delete', nil;
		else --} {
			return nil, 'HTTP method '..method..' not supported';
		end --}
	elseif (num == 3) then --} {
		if ((method ~= 'GET') and (method ~= 'PUT') and (method ~= 'POST') and (method ~= 'DELETE')) then -- {
			return nil, 'HTTP method '..method..' not supported';
		end -- }
		return url_parts[3], nil;
	else --} {
		return nil, 'Invalid URL'..request:get_uri();
	end --}
end
-- }

--{
handlers.handle_request = function (request, response)
	local flg, json_input = pcall(request.get_message_body_str, request);
	local n, url_parts = urlp.parse_url_path(request);
	local qp = urlp.get_qry_params(request);
	local json_parser = cjson.new();
	if (json_input == nil) then json_input = '{}'; end
	local flg, table_input, err =  pcall(json_parser.decode, json_input);
	local func, err = deduce_class_function(request, n, url_parts, qp);
	if (func == nil) then -- {
		print("in func == nil");
		response:set_status(400);
		response:set_chunked_trfencoding(true);
		response:set_content_type("application/json");
		response:send();
		response:write('{ "error": '..'"'..err..'"'..' }');
		return ;
	end -- }
	h = handlers[func];
	local table_output, err = h(qp, table_input);
	local flg, json_output, err = pcall(json_parser.encode, table_output);
	if (json_output == nil or json_output == '') then --{
		json_output = '{}';
	end -- }
	if (err ~= nil) then -- {
		if (err ~= 400 and err ~= 500) then -- {
			error('Invalid error code returned'..err);
		else -- } {
			response:set_status(err);
		end -- }
	else -- } {
		response:set_status(200);
	end -- }
	response:set_chunked_trfencoding(true);
	response:set_content_type("application/json");
	response:send();
	response:write(json_output);
	return ;
end
--}

req_handler_func_name = url_parts[1];
local request = platform.get_http_request();
local response = platform.get_http_response();
local func = handlers[req_handler_func_name];

return pcall(func, request, response);

