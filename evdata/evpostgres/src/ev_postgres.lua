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

local open_connetion_internal = function(host, port, dbname, user, password)
	local conn, msg = pg_lib.new(host, port, dbname, user, password);
	if (nil == conn) then
		return nil, msg;
	end
	local c = {_conn = conn}
	c = setmetatable(c, c_mt);
	return c;
end

ev_postgres_db.open_connetion = function(host, port, dbname, user, password)
	local conn, msg = open_connetion_internal(host, port, dbname, user, password)
	if (conn == nil) then
		error("ERROR INITIATING CONNECTION:"..msg);
		return nil;
	end
	if (nil == conn:turn_autocommit_off()) then
		error("COULD NOT TURN OFF AUTOCOMMIT");
		return nil;
	end

	return conn;
end

ev_postgres_stmt.execute = function(self)
	local flg, msg = self._stmt.execute(self._stmt)
	return flg, msg;
end

ev_postgres_conn.turn_autocommit_off = function(self)
	local flg, msg = self:rollback();
	if (not flg) then
		return flg, msg;
	end
	flg, msg = self:begin();
	return flg, msg;
end

ev_postgres_conn.begin = function(self)
	local bg_stmt = self:prepare("BEGIN");
	if (bg_stmt == nil) then
		error("COULD NOT PREPARE STATEMENTS FOR BEGIN");
		return nil;
	end
	local flg, msg = bg_stmt:execute();
	return flg, msg;
end

ev_postgres_conn.commit = function(self)
	local cm_stmt = self:prepare("COMMIT");
	if (cm_stmt == nil) then
		error("COULD NOT PREPARE STATEMENTS FOR COMMIT");
		return nil;
	end
	local flg, msg = cm_stmt:execute();
	return flg, msg;
end

ev_postgres_conn.rollback = function(self)
	local rb_stmt = self:prepare("ROLLBACK");
	if (rb_stmt == nil) then
		error("COULD NOT PREPARE STATEMENTS FOR ROLLBACK");
		return nil;
	end
	local flg, msg = rb_stmt:execute();
	return flg, msg;
end

ev_postgres_conn.prepare = function(self, sql_stmt)
	local stmt_src = ev_postgres_db.get_statement_id(debug.getinfo(2));
	local c_p_stmt, msg = self._conn.prepare(self._conn, stmt_src, sql_stmt);
	if (c_p_stmt == nil) then
		error("Could not prepare statement: "..sql_stmt.. ":"..msg);
		return nil;
	end
	local p_stmt = { stmt_src = stmt_src, _stmt = c_p_stmt };
	p_stmt = setmetatable(p_stmt, s_mt);
	return p_stmt;
end

return ev_postgres_db;

