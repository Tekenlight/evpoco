function handle_request() -- {
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();
	response:set_chunked_trfencoding(true);
	response:set_content_type("text/html");
	response:send();


	response:write('<html>\n');
	response:write('<head>\n');
	response:write('<title>EVLUA Form Server Sample</title>\n');
	response:write('</head>\n');
	response:write('<body>\n');
	response:write('<h1>EVLUA Form Server Sample</h1>\n');
	response:write('<h2>GET Form</h2>\n');
	response:write('<form method=\"GET\" action=\"/formserver.lua/handle_request\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"GET\">\n');
	response:write('</form>\n');
	response:write('<h2>POST Form</h2>\n');
	response:write('<form method=\"POST\" action=\"/formserver.lua/handle_post\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"POST\">\n');
	response:write('</form>\n');
	response:write('<h2>File Upload</h2>\n');
	response:write('<form method=\"POST\" action=\"/formserver.lua/handle_upload\" enctype=\"multipart/form-data\">\n');
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

	db = require('rdbms_interface');
	--print('connect')
	c = assert(db.Connect('sqlite','test.db'));
	--print('prepare')
	s = assert(c:prepare('select org_id, org_name from org where org_name like :ORG_NAME'));

	--print('columns')
	col = assert(s:columns());
	--for i,v in ipairs(col) do
		--print(v);
	--end
	local ORG_NAME = '%Ltd';
	--print('execute')
	assert(s:execute(ORG_NAME));

	local base = require "cjson"
	local cjson = base.new();

	json_text = '{ "one": 1, "two" : [ true, { "foo": "bar" } ] }'
	value = cjson.decode(json_text);

	--for n,v in pairs(value) do
		--print(n,v);
		--if (type(v) == "table") then
			--for p,q in pairs(v) do
				--print(p,q);
			--end
		--end
	--end



	response:write('<p>');
	response:write('<table>');
	response:write('<tr>')
	response:write('<td>'..col[1]..'</td>'..'<td>'..col[2]..'</td>');
	response:write('</tr>')

	for row in s:rows(1) do
		response:write('<tr>')
		response:write('<td>'..row['org_id']..'</td>'..'<td>'..row['org_name']..'</td>');
		response:write('</tr>')
	end

	response:write('</table>\n');
	response:write('</p>');

	
	local mongo = require 'mongo'
	local client = mongo.Client('mongodb://127.0.0.1');
	--print(mongo.BSON{org_id="prathisthan", org_name = "Prathishthan Software Ventures Pvt Ltd", ts_cnt = 1}) -- From table (order is unspecified)
	--print(mongo.BSON({a = { b = 2, c = 3}})) -- From table (order is unspecified)
	--print(mongo.BSON('{"org_id" : { "$eq" : "tekenlight"}}'))
	--for n,v in pairs(client:getDatabaseNames()) do
		--print(n,v);
	--end

	db = client:getDatabase('examples');
	collection= db:getCollection('companies');
	local query1 = mongo.BSON('{"org_id" : { "$eq" : "tekenlight"}}')
	local cursor = collection:find(mongo.BSON('{"org_id" : { "$eq" : "tekenlight"}}'));
	for doc in cursor:iterator() do
		for n,v in pairs(doc) do
			print(n,v);
		end
	end

	response:write('</body>\n');


	--print('autocommit')
	local b=c:autocommit(false);
	--print('commit')
	local b=c:commit();
	--print('rollback')
	local b=c:rollback();
	--print('HH',b,'HH');
	--

	return ;
end -- }

function handle_upload()
	print('Hello from LUA handler');
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();
	response:set_chunked_trfencoding(true);
	response:set_content_type("text/html");
	response:send();
	response:write('<html>\n');
	response:write('<head>\n');
	response:write('<title>EVLUA Form Server Sample</title>\n');
	response:write('</head>\n');
	response:write('<body>\n');
	response:write('<h1>EVLUA Form UPLOAD Server Sample</h1>\n');
	response:write('<h2>GET Form</h2>\n');
	response:write('<form method=\"GET\" action=\"/formserver.lua/handle_request\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"GET\">\n');
	response:write('</form>\n');
	response:write('<h2>POST Form</h2>\n');
	response:write('<form method=\"POST\" action=\"/formserver.lua/handle_post\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"POST\">\n');
	response:write('</form>\n');
	response:write('<h2>File Upload</h2>\n');
	response:write('<form method=\"POST\" action=\"/formserver.lua/handle_upload\" enctype=\"multipart/form-data\">\n');
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

	response:write('</body>\n');

	return ;
end

function handle_post() -- {
	local return_string = 'Hello from LUA handler';
	local request = platform.get_http_request();
	local form = request:parse_req_form();
	local response = platform.get_http_response();
	response:set_chunked_trfencoding(true);
	response:set_content_type("text/html");
	response:send();
	response:write('<html>\n');
	response:write('<head>\n');
	response:write('<title>EVLUA Form Server Sample</title>\n');
	response:write('</head>\n');
	response:write('<body>\n');
	response:write('<h1>EVLUA Form POST Server Sample</h1>\n');
	response:write('<h2>GET Form</h2>\n');
	response:write('<form method=\"GET\" action=\"/formserver.lua/handle_request\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"GET\">\n');
	response:write('</form>\n');
	response:write('<h2>POST Form</h2>\n');
	response:write('<form method=\"POST\" action=\"/formserver.lua/handle_post\">\n');
	response:write('<input type=\"text\" name=\"text\" size=\"31\">\n');
	response:write('<input type=\"submit\" value=\"POST\">\n');
	response:write('</form>\n');
	response:write('<h2>File Upload</h2>\n');
	response:write('<form method=\"POST\" action=\"/formserver.lua/handle_upload\" enctype=\"multipart/form-data\">\n');
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

	return ;
end --}

local arg = {...}
req_handler_func_name = arg[1];
local func = load('return '..req_handler_func_name..'()');

return pcall(func);

