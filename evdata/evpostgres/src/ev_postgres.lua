local pg = package.loadlib('libevpostgres.so','luaopen_evrdbms_postgres');
local loaded, pg_lib = pcall(pg);
if(not loaded) then
	error("Could not load library");
end

local ev_postgres_conn = {};
local ev_postgres_stmt = {};
local ev_postgres_db = {};

local c_mt = { __index = ev_postgres_conn };
local s_mt = { __index = ev_postgres_stmt };

ev_postgres_db.get_statement_id = function(dinfo)
	local id = dinfo.source..":"..dinfo.currentline;
	return id;
end

ev_postgres_db.open_connetion = function(host, dbname, user, password)
	--print(debug.getinfo(1).source, debug.getinfo(1).currentline, host);
	--print(debug.getinfo(1).source, debug.getinfo(1).currentline, dbname);
	--print(debug.getinfo(1).source, debug.getinfo(1).currentline, user);
	--print(debug.getinfo(1).source, debug.getinfo(1).currentline, password);
	--print(debug.getinfo(1).source, debug.getinfo(1).currentline, L);

	local conn = pg_lib.new(host, dbname, user, password);
	if (nil == conn) then
		error("ERROR INITIATING CONNECTION");
		return nil;
	end
	local c = {_conn = conn}
	c = setmetatable(c, c_mt);
	return c;
end

ev_postgres_conn.prepare = function(self, sql_stmt)
	local stmt_id = ev_postgres_db.get_statement_id(debug.getinfo(2));
	local c_p_stmt = self._conn.prepare(self._conn, stmt_id, sql_stmt);
	if (c_p_stmt == nil) then
		error("Could not prepare statement: "..sql_stmt);
		return nil;
	end
	local p_stmt = { stmt_id = stmt_id, _stmt = c_p_stmt };
	p_stmt = setmetatable(p_stmt, s_mt);
	return p_stmt;
end

return ev_postgres_db;

