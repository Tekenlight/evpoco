
platform.ev_dbg_pthread_self("async_task.lua");
--platform.ev_hibernate(5);
local args = {...};

while(1) do
	local ws_util = require('service_utils.WS.ws_util');
	local conn = ws_util.get_ws_from_pool("001");
	if (conn) then
		local obj = { command = "MSGNOTIFICATION", topic = "001" };
		local cjson = require('cjson.safe');
		local json_parser = cjson.new();
		local str = json_parser.encode(obj);
		ws_util.send_msg(conn, str );
		ws_util.add_ws_to_pool(conn, "001");
	end
	platform.ev_hibernate(4);
end


print(debug.getinfo(1).source, debug.getinfo(1).currentline);

topic = args[1];
