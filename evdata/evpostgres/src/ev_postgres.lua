local ffi = require("ffi");
local bc = require("bigdecimal");
local du = require('lua_schema.date_utils');
local cu = require('lua_schema.core_utils');
local pg = package.loadlib('libevpostgres.so','luaopen_evrdbms_postgres');
local types = require('ev_types');
local loaded, pg_lib = pcall(pg);
if(not loaded) then
	error("Could not load library");
end

ffi.cdef[[

struct lua_bind_variable_s {
	int    type;
	void*  val;
	size_t size;
	const char * name;
};
typedef struct lua_bind_variable_s lua_bind_var_s_type;
typedef struct lua_bind_variable_s* lua_bind_var_p_type;

void * memcpy(void *restrict dst, const void *restrict src, size_t n);
void free(void *ptr);
size_t strlen(const char *s);
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
	local strings = {}; -- This is to ensure, no loss of data due to gc
	local ints = {}; -- This is to ensure, no loss of data due to gc
	local inp_args = {...}
	local i = 1;
	while (i <= #inp_args) do
		v = select(i, table.unpack(inp_args));
		if (type(v) == 'nil') then
			local nullptr = ffi.new("void *", 0);
			local bind_var = ffi.new("lua_bind_variable_s", 0);
			bind_var.type = types.name_to_id.nullptr;
			bind_var.val = ffi.getptr(nullptr);
			bind_var.size = 8;
			args[i] = ffi.getptr(bind_var);
		elseif (type(v) == 'cdata') then
			if (ffi.istype("hex_data_s_type", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id.binary;
				bind_var.val = ffi.getptr(v.value);
				bind_var.size = v.size;
				args[i] = ffi.getptr(bind_var);
			elseif (ffi.istype("dt_s_type", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id[du.tid_name_map[v.type]];
				if (bind_var.type == ffi.C.ev_lua_date) then
					ints[#ints+1] = du.daynum_from_dtt(v);
					bind_var.size = 4;
				elseif (bind_var.type == ffi.C.ev_lua_time) then
					ints[#ints+1] = du.time_from_dtt(v);
					bind_var.size = 8;
				else
					ints[#ints+1] = du.long_from_dtt(v);
					bind_var.size = 8;
				end
				bind_var.val = ffi.getptr(ints[#ints]);
				args[i] = ffi.getptr(bind_var);
			elseif (ffi.istype("dur_s_type", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id['duration'];
				bind_var.val = v.value;
				bind_var.size = ffi.C.strlen(v.value);
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("float", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id.float
				bind_var.val = ffi.getptr(v);
				bind_var.size = 4;
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("int16_t", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id.int16_t
				bind_var.val = ffi.getptr(v);
				bind_var.size = 2;
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("int32_t", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id.int32_t
				bind_var.val = ffi.getptr(v);
				bind_var.size = 4;
				args[i] = ffi.getptr(bind_var);
			elseif ( ffi.istype("int64_t", v)) then
				local bind_var = ffi.new("lua_bind_variable_s", 0);
				bind_var.type = types.name_to_id.int64_t
				bind_var.val = ffi.getptr(v);
				bind_var.size = 8;
				args[i] = ffi.getptr(bind_var);
			elseif (
				ffi.istype("int8_t", v) or
				ffi.istype("uint64_t", v) or
				ffi.istype("uint8_t", v) or
				ffi.istype("uint16_t", v) or
				ffi.istype("uint32_t", v)
				) then
				print(debug.getinfo(1).source, debug.getinfo(1).currentline, i);
				error("Datatype (unsigned or 8 bit integer), not supported by PostgreSQL");
				return false, "Datatype (unsigned or 8 bit integer), not supported by PostgreSQL";
			else
				error("Datatype not supported by PostgreSQL ["..i.."]");
				return false, "Datatype not supported by PostgreSQL";
			end
		elseif (type(v) == 'userdata' and v.__name == 'bc bignumber') then
			strings[#strings+1] = tostring(v);
			local bind_var = ffi.new("lua_bind_variable_s", 0);
			bind_var.type = types.name_to_id.decimal
			bind_var.val = strings[#strings];
			bind_var.size = #strings[#strings];
			args[i] = ffi.getptr(bind_var);
		else -- These are all  lua types
			if (type(v) ~= 'string' and type(v) ~= 'number' and type(v) ~= 'boolean') then
				error("Unsupported datatype ["..type(v).."]");
				return false, "Unsupported datatype ["..type(v).."]";
			end
			args[i] = v;
		end
		i = i + 1;
	end
	local flg, msg = self._stmt.execute(self._stmt, table.unpack(args));
	return flg, msg;
end

local split_field = function(s)
	local strings = {};
	local i = 0;
	for w in string.gmatch(s, "[^.]+") do
		i = i + 1;
		strings[i] = w;
	end
	return i, strings;
end

ev_postgres_stmt.map = function(q_out, fields)
	if (type(fields) ~= 'table') then
		error("Invalid inputs");
		return nil;
	end
	if (#fields ~= #q_out) then
		error("Invalid inputs");
		return nil;
	end
	local out = {};
	for i,v in ipairs(fields) do
		local n, s_f = split_field(v);
		if (n == nil or n == 0) then
			error("Invalid inputs");
		elseif (n == 1) then
			if (ffi.istype("void*", q_out[i]) and q_out[i] == ffi.NULL) then
				out[s_f[1]] = nil;
			else
				out[s_f[1]] = q_out[i];
			end
		else
			local j = 1;
			local t = out;
			while (j<n) do
				if (t[s_f[j]] == nil) then
					t[s_f[j]] = {};
				end
				t = t[s_f[j]];
				j = j + 1;
			end
			if (ffi.istype("void*", q_out[i]) and q_out[i] == ffi.NULL) then
				t[s_f[j]] = nil;
			else
				t[s_f[j]] = q_out[i];
			end
		end
	end
	return out;
end

ev_postgres_stmt.fetch_result = function(self)

	local lua_values, n_col, c_row = self._stmt:fetch();
	if (lua_values == nil) then
		return nil;
	end

	local row = ffi.cast("lua_bind_variable_s*", c_row);
	local i = 0;
	local out = {};
	while (i < n_col) do
		if (row[i].type == ffi.C.ev_lua_string) then
			out[i+1] = lua_values[i+1];
		elseif (row[i].type == ffi.C.ev_lua_date) then
			local v = ffi.new("int64_t");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = du.dtt_from_long(v, 'date', nil);
		elseif (row[i].type == ffi.C.ev_lua_datetime) then
			local v = ffi.new("int64_t");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = du.dtt_from_long(v, 'dateTime', nil);
		elseif (row[i].type == ffi.C.ev_lua_time) then
			local v = ffi.new("int64_t");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = du.dtt_from_long(v, 'time', nil);
		elseif (row[i].type == ffi.C.ev_lua_number) then
			out[i+1] = lua_values[i+1];
		elseif (row[i].type == ffi.C.ev_lua_float) then
			local v = ffi.new("float");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = v;
		elseif (row[i].type == ffi.C.ev_lua_decimal) then
			local v = bc.new(lua_values[i+1]);
			out[i+1] = v;
		elseif (row[i].type == ffi.C.ev_lua_binary) then
			local v = ffi.new("hex_data_s_type");
			v.size = row[i].size;
			v.value = cu.alloc(v.size);
			ffi.C.memcpy(v.value, row[i].val, v.size);
			out[i+1] = v;
		elseif (row[i].type == ffi.C.ev_lua_boolean) then
			out[i+1] = lua_values[i+1];
		elseif (row[i].type == ffi.C.ev_lua_int16_t) then
			local v = ffi.new("int16_t");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = v;
		elseif (row[i].type == ffi.C.ev_lua_int32_t) then
			local v = ffi.new("int32_t");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = v;
		elseif (row[i].type == ffi.C.ev_lua_int64_t) then
			local v = ffi.new("int64_t");
			ffi.C.memcpy(ffi.getptr(v), row[i].val, row[i].size);
			out[i+1] = v;
		elseif (row[i].type == ffi.C.ev_lua_duration) then
			local v = ffi.new("interval_p_type", row[i].val);
			local dur = du.dur_from_bin(v);
			out[i+1] = dur;
		elseif (row[i].type == ffi.C.ev_lua_nullptr) then
			out[i+1] = ffi.NULL;
		else
			error('Unsupported type '..row[i].type);
		end
		i = i+1;
	end
	ffi.C.free(c_row);
	return out;
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
	print(debug.getinfo(1).source, debug.getinfo(1).currentline);
	local ed_stmt = self:prepare("ROLLBACK WORK");
	if (ed_stmt == nil) then
		error("COULD NOT PREPARE STATEMENTS FOR BEGIN");
		return nil;
	end
	print(debug.getinfo(1).source, debug.getinfo(1).currentline);
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

