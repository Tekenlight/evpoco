local url_parts = {...}
urlp = require('rest_url_parser');
cjson = require('cjson.safe');
mongo = require('mongo');
roc_params = require('roc_db_param');
mcm = require('mongo_connection_manager');

local handlers = {};

handlers.list= function (company_name)
	print('LIST');
	local db_handle = mcm.connect(roc_params.db_url, roc_params.db_schema, roc_params.db_user_id, roc_params.db_user_password);
	return;
end

handlers.add= function (company)
	return;
end

handlers.modify= function ()
	return;
end

handlers.fetch= function ()
	return;
end

handlers.delete= function ()
	return;
end

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
local function deduce_class_function(request, num, url_parts, qp)
	local method = request:get_method();
	print(num, method);
	if (num == 1) then -- {
		if (method ~= 'GET') then -- {
			print("HERE");
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
			print("Here");
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

handlers.handle_request = function (request, response)
	local flg, json_input = pcall(request.get_message_body_str, request);
	local n, url_parts = urlp.parse_url_path(request);
	local qp = urlp.get_qry_params(request);
	json_parser = cjson.new();
	if (json_input == nil) then json_input = '{}'; end
	local flg, input, err =  pcall(json_parser.decode, json_input);
	local func, err = deduce_class_function(request, n, url_parts, qp);
	print(func);
	if (func == nil) then --{
		print("in func == nil");
		response:set_status(400);
		response:set_chunked_trfencoding(true);
		response:set_content_type("application/json");
		response:send();
		response:write('{"error": ');
		response:write('"'..err..'"');
		response:write('}');
		return ;
	end --}
	h = handlers[func];
	print('HIHIHIHI');
	return h(input);
end


req_handler_func_name = url_parts[1];
local request = platform.get_http_request();
local response = platform.get_http_response();
local func = handlers[req_handler_func_name];

return pcall(func, request, response);

