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
handlers.list= function (self, db_handle, url_parts, query_params)
	local fields = {"org_id", "org_name"};
	local collection = db_handle:getCollection('companies');
	local criteria = get_criteria(fields, query_params);
	if (criteria == nil) then -- {
		criteria = {};
	end -- }
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

--{
handlers.validateForAdd = function(self, db_handle, company)
	if (company.org_id == nil or company.org_id == '') then -- {
		return -1, "org_id is a manadatory field";
	end -- }
	if (company.org_name == nil or company.org_name == '') then -- {
		return -1, "org_name is a manadatory field";
	end -- }
	local collection = db_handle:getCollection('companies');
	local query = {};
	query = { ["data.org_id"] = { ["$eq"] = company.org_id } };
	doc, err = collection:findOne(query);
	if (err ~= nil) then -- {
		error(err);
		return -1, err;
	end -- }
	print(doc);
	if (doc ~= nil) then -- {
		return -1, "Record with id "..company.org_id.." already exists";
	end -- }
	return 0, nil;
end
--}

-- {
handlers.add= function (self, db_handle, url_parts, query_params, company)
	local ret, errmsg = self:validateForAdd(db_handle, company);
	print(ret, errmsg);
	if (ret ~= 0) then -- {
		return { errcode=-1,  message = errmsg }, 400;
	end -- }
	company.ts_cnt = 1;
	local collection = db_handle:getCollection('companies');
	local envelope = { data = company };
	local flg, err = collection:insert(envelope)

	print(flg, err);

	local error_code = nil;
	local table_out = {};
	if (flg ~= nil and flg == true ) then -- {
		table_out = { message = "Record inserted"};
	else -- } {
		error_code = 400;
		table_out = { errcode = -1,  errmsg = err };
	end --}

	return table_out, error_code;
end
-- }

-- {
handlers.fetch= function (self, db_handle, url_parts, query_params)
	local org_id = url_parts[2];
	local err = 200;
	local result = {};
	if (org_id == nil or org_id == '') then -- {
		err = 400;
		result.msg = "org_id is mandatory"
		result.errcode = -1;
		return result, err;
	end --}
	local collection = db_handle:getCollection('companies');
	local query = {};
	query = { ["data.org_id"] = { ["$eq"] = org_id } };
	local projection  = { projection = { data = 1, _id = 0 } };
	doc = collection:findOne(mongo.BSON(query), mongo.BSON(projection));
	if (doc == nil) then -- {
		return { errcode = 1403, errmsg = "Record not found" }, 400
	else -- } { 
		return doc:value().data, nil;
	end -- }
end
-- }

--{
handlers.validateForModify = function(self, db_handle, company)
	if (company.org_id == nil or company.org_id == '') then -- {
		return -1, "org_id is a manadatory field";
	end -- }
	if (company.org_name == nil or company.org_name == '') then -- {
		return -1, "org_name is a manadatory field";
	end -- }
	if (company.ts_cnt == nil or company.ts_cnt == '') then -- {
		return -1, "original ts_cnt should be submitted as part of the document during modify";
	end -- }
	local collection = db_handle:getCollection('companies');
	local query = {};
	query = { ["data.org_id"] = { ["$eq"] = company.org_id } };
	doc, err = collection:findOne(query);
	if (err ~= nil) then -- {
		error(err);
		return -1, err;
	end -- }
	print(doc);
	if (doc == nil) then -- {
		return -1, "Record with id "..company.org_id.." does not exist";
	end -- }
	return 0, nil;
end
--}

-- {
handlers.modify= function (self, db_handle, url_parts, query_params, company)
	local ret, errmsg = self:validateForModify(db_handle, company);
	if (ret ~= 0) then -- {
		return { message = errmsg }, 400;
	end -- }
	local collection = db_handle:getCollection('companies');
	local old_ts_cnt = company.ts_cnt
	local query_part1 = { ["data.org_id"] = { ["$eq"] = company.org_id } };
	local query_part2 = { ["data.ts_cnt"] = { ["$eq"] = math.tointeger(old_ts_cnt) } };
	local query = { ["$and"] = { __array=true, query_part1, query_part2 }};
	company.ts_cnt = company.ts_cnt + 1;
	old_doc, err = collection:findAndModify(mongo.BSON(query), {update = {data = company}});
	local error_code = nil;
	local table_out = {};
	if (old_doc ~= nil and err == nil) then -- {
		table_out = { message = "Record updated"};
	else -- } {
		error_code = 400;
		if (err ~= nil) then -- {
			table_out = { message = err };
		else -- } {
			table_out = { errcode = 1403,
				message = "Record not found, org_id: "..company.org_id..", ts_cnt: "..math.tointeger(old_ts_cnt)} ;
		end -- }
	end --}

	return table_out, error_code;
end
-- }

--{
handlers.validateForDelete = function(self, db_handle, company)
	if (company.org_id == nil or company.org_id == '') then -- {
		return -1, "org_id is a manadatory field";
	end -- }
	if (company.ts_cnt == nil or company.ts_cnt == '') then -- {
		return -1, "original ts_cnt should be submitted as part of the document during modify";
	end -- }
	local collection = db_handle:getCollection('companies');
	local query = {};
	query = { ["data.org_id"] = { ["$eq"] = company.org_id } };
	doc, err = collection:findOne(query);
	if (err ~= nil) then -- {
		error(err);
		return -1, err;
	end -- }
	print(doc);
	if (doc == nil) then -- {
		return -1, "Record with id "..company.org_id.." does not exist";
	elseif (doc:value().data.deleted == 1) then -- } {
		return -1, "Record with id "..company.org_id.." is logically deleted";
	end -- }
	return 0, nil;
end
--}

-- {
handlers.delete= function (self, db_handle, url_parts, query_params, company)
	if (company == nil) then -- {
		return { errcode = -1, errmsg = "Company data not submitted for deletion" }
	end -- }
	local ret, errmsg = self:validateForDelete(db_handle, company);
	if (ret ~= 0) then -- {
		return { message = errmsg }, 400;
	end -- }
	local collection = db_handle:getCollection('companies');
	local old_ts_cnt = company.ts_cnt
	local query_part1 = { ["data.org_id"] = { ["$eq"] = company.org_id } };
	local query_part2 = { ["data.ts_cnt"] = { ["$eq"] = math.tointeger(old_ts_cnt) } };
	local query = { ["$and"] = { __array=true, query_part1, query_part2 }};
	company.ts_cnt = company.ts_cnt + 1;
	old_doc, err = collection:findAndModify(mongo.BSON(query), {update = { ["$set"] = {["data.deleted"] = 1}}});
	local error_code = nil;
	local table_out = {};
	if (old_doc ~= nil and err == nil) then -- {
		table_out = { message = "Record logically deleted"};
	else -- } {
		error_code = 400;
		if (err ~= nil) then -- {
			table_out = { message = err };
		else -- } {
			table_out = { errcode = 1403,
				message = "Record not found, org_id: "..company.org_id..", ts_cnt: "..math.tointeger(old_ts_cnt)} ;
		end -- }
	end --}

	return table_out, error_code;
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
local function deduce_method(request, num, url_parts, qp)
	local method = request:get_method();
	if (num == 1) then -- {
		if (method ~= 'GET') then -- {
			if (method == 'POST') then -- {
				return 'add', nil;
			elseif (method == 'PUT') then -- } {
				return 'modify', nil;
			elseif (method == 'DELETE') then -- } {
				return 'delete', nil;
			else -- } {
				return nil, 'HTTP method '..method..' not supported';
			end -- }
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
local handle_request = function (request, response)
	local flg, json_input = pcall(request.get_message_body_str, request);
	local n, url_parts = urlp.parse_url_path(request);
	local qp = urlp.get_qry_params(request);
	local json_parser = cjson.new();
	if (json_input == nil) then json_input = '{}'; end
	local flg, table_input, err =  pcall(json_parser.decode, json_input);
	local func, err = deduce_method(request, n, url_parts, qp);
	if (func == nil) then -- {
		print("in func == nil");
		response:set_status(400);
		response:set_chunked_trfencoding(true);
		response:set_content_type("application/json");
		response:send();
		response:write('{ "error": '..'"'..err..'"'..' }');
		return ;
	end -- }
	local db_handle = mcm.connect(roc_params.db_url, roc_params.db_schema_name, roc_params.db_user_id, roc_params.db_user_password);
	h = handlers[func];
	local table_output, err = h(handlers, db_handle, url_parts, qp, table_input);
	if (err ~= nil) then -- {
		if (err ~= 400 and err ~= 500) then -- {
			error('Invalid error code returned '..err);
		else -- } {
			response:set_status(err);
		end -- }
	else -- } {
		response:set_status(200);
	end -- }
	local flg, json_output, err = pcall(json_parser.encode, table_output);
	if (json_output == nil or json_output == '') then --{
		json_output = '{}';
	end -- }
	response:set_chunked_trfencoding(true);
	response:set_content_type("application/json");
	response:send();
	response:write(json_output);
	return ;
end
--}

local request = platform.get_http_request();
local response = platform.get_http_response();

return pcall(handle_request, request, response);

