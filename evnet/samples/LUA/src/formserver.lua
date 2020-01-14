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
	c = assert(db.Connect('sqlite','test.db'));
	print(c);
	s = assert(c:prepare('select org_id, org_name from org'));

	assert(s:execute());

	col = assert(s:columns());

	response:write('<p>');
	response:write('<table>');
	response:write('<tr>')
	response:write('<td>'..col[1]..'</td>'..'<td>'..col[2]..'</td>');
	response:write('</tr>')

	for row in s:rows() do
		response:write('<tr>')
		response:write('<td>'..row[1]..'</td>'..'<td>'..row[2]..'</td>');
		response:write('</tr>')
	end

	response:write('</table>\n');
	response:write('</p>');

	response:write('</body>\n');

	local b=c:rollback();
	local b=c:autocommit(false);
	print('HH',b,'HH');

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
