local ffi = require("ffi");
local bc = require("bigdecimal");
local du = require('date_utils');
local pg = package.loadlib('libevpostgres.so','luaopen_evrdbms_postgres');
local types = require('ev_types');
local loaded, pg_lib = pcall(pg);
if(not loaded) then
	error("Could not load library");
end

ffi.cdef[[
struct lu_bind_variable_s {
	int    type;
	void*  val;
	size_t size;
};
typedef struct lu_bind_variable_s lua_bind_var_s_type;
typedef struct lu_bind_variable_s* lua_bind_var_p_type;
]]

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

	return conn;
end

ev_postgres_stmt.columns = function(self)
	local out = self._stmt.columns(self._stmt)
	return out;
end

ev_postgres_stmt.execute = function(self, ...)
	local args = {};
	local strings {}; -- This is to ensure, no loss of data due to gc
	for i,v in ipairs({...}) do
		if (type(v) == 'cdata') then
			if (ffi.istype("b64_data_s_type", v)) then
				local bind_var = ffi.new("lu_bind_variable_s", 0);
				bind_var.type = types.name_to_id.binary;
				bind_var.val = v.value;
				bind_var.size = v.size;
				args[i] = ffi.getptr(bind_var);
			elseif (ffi.istype("hex_data_s_type", v)) then
				local bind_var = ffi.new("lu_bind_variable_s", 0);
				bind_var.type = types.name_to_id.binary;
				bind_var.val = v.value;
				bind_var.size = v.size;
				args[i] = ffi.getptr(bind_var);
			elseif (ffi.istype("dt_s_type", v)) then
				strings[#strings+1] = tostring(v);
				local bind_var = ffi.new("lu_bind_variable_s", 0);
				bind_var.type = types.name_to_id[du.tid_name_map[v.format]];
				bind_var.val = strings[#strings];
				bind_var.size = #strings[#strings];
				args[i] = ffi.getptr(bind_var);
			elseif (ffi.istype("dur_s_type", v)) then
				strings[#strings+1] = tostring(v);
				local bind_var = ffi.new("lu_bind_variable_s", 0);
				bind_var.type = types.name_to_id.duration
				bind_var.val = strings[#strings];
				bind_var.size = #strings[#strings];
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("int16_t", v)) then
				local bind_var = ffi.new("lu_bind_variable_s", 0);
				bind_var.type = types.name_to_id.int16_t
				bind_var.val = ffi.getptr(v);
				bind_var.size = 2;
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("int32_t", v)) then
				local bind_var = ffi.new("lu_bind_variable_s", 0);
				bind_var.type = types.name_to_id.int32_t
				bind_var.val = ffi.getptr(v);
				bind_var.size = 4;
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("int64_t", v)) then
			elseif (
				ffi.istype("int8_t", v) or
				ffi.istype("uint64_t", v) or
				ffi.istype("uint8_t", v) or
				ffi.istype("uint16_t", v) or
				ffi.istype("uint32_t", v) or
				) then
				error("Datatype (unsigned or 8 bit integer), not supported by PostgreSQL");
				return false, "Datatype (unsigned or 8 bit integer), not supported by PostgreSQL";
			else
				error("Datatype not supported by PostgreSQL");
				return false, "Datatype not supported by PostgreSQL";
			end
		elseif (type(v) == 'userdata' and v.__name = 'bc bignumber') then
			args[i] = tostring(v);
		else -- These are all  lua types
			if (type(v) ~= 'string' and type(v) ~= 'number' and type(v) ~= nil  and type(v) ~= 'bool') then
				error("Unsupported datatype ["..type(v).."]");
				return false, "Unsupported datatype ["..type(v).."]";
			end
			args[i] = v;
		end
	end
	local flg, msg = self._stmt.execute(self._stmt, table.unpack(args));
	return flg, msg;
end

local turn_autocommit_off = function(self)
	local flg, msg = self:begin();
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

ev_postgres_conn.end_tran = function(self)
	local ed_stmt = self:prepare("ROLLBACK WORK");
	if (ed_stmt == nil) then
		error("COULD NOT PREPARE STATEMENTS FOR BEGIN");
		return nil;
	end
	local flg, msg = ed_stmt:execute();
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

