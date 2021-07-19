local ffi = require('ffi');

ffi.cdef[[
typedef enum {
	ev_lua_string = 1,
	ev_lua_date,
	ev_lua_datetime,
	ev_lua_time,
	ev_lua_byte,
	ev_lua_number,
	ev_lua_integer,
	ev_lua_decimal,
	ev_lua_binary,
	ev_lua_boolean,
	ev_lua_int8_t,
	ev_lua_uint8_t,
	ev_lua_int16_t,
	ev_lua_uint16_t,
	ev_lua_int32_t,
	ev_lua_uint32_t,
	ev_lua_int64_t,
	ev_lua_uint64_t,
	ev_lua_duration,
	ev_lua_float,
	ev_lua_nullptr,
} ev_lua_datatypes;

]]

local id_to_name = {
	'string',    -- 1
	'date',      -- 2
	'dateTime',  -- 3
	'time',      -- 4
	'byte',      -- 5
	'number',    -- 6
	'integer',   -- 7
	'decimal',   -- 8
	'binary',    -- 9
	'boolean',   -- 10
	'int8_t',    -- 11
	'uint8_t',   -- 12
	'int16_t',   -- 13
	'uint16_t',  -- 14
	'int32_t',   -- 15
	'uint32_t',  -- 16
	'int64_t',   -- 17
	'uint64_t',  -- 18
	'duration',  -- 19
	'float',     -- 20
	'nullptr',   -- 21
};

local name_to_id = {
	['string']       = ffi.C.ev_lua_string, -- varchar, char,
	['date']         = ffi.C.ev_lua_date,
	['dateTime']     = ffi.C.ev_lua_datetime, 
	['time']         = ffi.C.ev_lua_time, 
	['byte']         = ffi.C.ev_lua_byte, 
	['number']       = ffi.C.ev_lua_number,
	['integer']      = ffi.C.ev_lua_integer,
	['decimal']      = ffi.C.ev_lua_decimal,
	['binary']       = ffi.C.ev_lua_binary,
	['boolean']      = ffi.C.ev_lua_boolean,
	['int8_t']       = ffi.C.ev_lua_int8_t,
	['uint8_t']      = ffi.C.ev_lua_uint8_t,
	['int16_t']      = ffi.C.ev_lua_int16_t,
	['uint16_t']     = ffi.C.ev_lua_uint16_t,
	['int32_t']      = ffi.C.ev_lua_int32_t,
	['uint32_t']     = ffi.C.ev_lua_uint32_t,
	['int64_t']      = ffi.C.ev_lua_int64_t,
	['uint64_t']     = ffi.C.ev_lua_uint64_t,
	['duration']     = ffi.C.ev_lua_duration,
	['float']      = ffi.C.ev_lua_float,
	['nullptr']      = ffi.C.ev_lua_nullptr,
};

local ev_type_dict = {
	['string']       = require('org.w3.2001.XMLSchema.string_handler'):instantiate(),
	['date']         = require('org.w3.2001.XMLSchema.date_handler'):instantiate(),
	['dateTime']     = require('org.w3.2001.XMLSchema.dateTime_handler'):instantiate(), 
	['time']         = require('org.w3.2001.XMLSchema.time_handler'):instantiate(), 
	['byte']         = require('org.w3.2001.XMLSchema.byte_handler'):instantiate(), 
	['number']       = require('org.w3.2001.XMLSchema.double_handler'):instantiate(),
	['integer']      = require('org.w3.2001.XMLSchema.integer_handler'):instantiate(),
	['decimal']      = require('org.w3.2001.XMLSchema.decimal_handler'):instantiate(),
	['binary']       = require('org.w3.2001.XMLSchema.hexBinary_handler'):instantiate(),
	['boolean']      = require('org.w3.2001.XMLSchema.boolean_handler'):instantiate(),
	['int8_t']       = require('org.w3.2001.XMLSchema.byte_handler'):instantiate(),
	['uint8_t']      = require('org.w3.2001.XMLSchema.unsignedByte_handler'):instantiate(),
	['int16_t']      = require('org.w3.2001.XMLSchema.short_handler'):instantiate(),
	['uint16_t']     = require('org.w3.2001.XMLSchema.unsignedShort_handler'):instantiate(),
	['int32_t']      = require('org.w3.2001.XMLSchema.int_handler'):instantiate(),
	['uint32_t']     = require('org.w3.2001.XMLSchema.unsignedInt_handler'):instantiate(),
	['int64_t']      = require('org.w3.2001.XMLSchema.long_handler'):instantiate(),
	['uint64_t']     = require('org.w3.2001.XMLSchema.unsignedLong_handler'):instantiate(),
	['duration']     = require('org.w3.2001.XMLSchema.duration_handler'):instantiate(),
	['float']        = require('org.w3.2001.XMLSchema.float_handler'):instantiate(),
	['nullptr']      = nil,
}

local ev_type_index = {
	id_to_name = id_to_name,
	name_to_id = name_to_id,
	type_dict = ev_type_dict,
};

return ev_type_index;

