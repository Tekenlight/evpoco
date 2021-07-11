local id_to_name = {
	'string',    -- 1
	'date',      -- 2
	'datetime',  -- 3
	'time',      -- 4
	'byte',      -- 5
	'short',     -- 6
	'int',       -- 7
	'long',      -- 8
	'number',    -- 9
	'integer',   -- 10
	'decimal',   -- 11
	'binary',    -- 12
	'boolean',   -- 13
	'int16_t',   -- 14
	'int32_t',   -- 15
	'int64_t',   -- 16
	'duration',  -- 17
};
local name_to_id = {
	['string'] =    1,
	['date'] =      2,
	['datetime'] =  3, 
	['time'] =      4, 
	['byte'] =      5, 
	['short'] =     6,
	['int'] =       7,
	['long'] =      8,
	['number'] =    9,
	['integer'] =   10,
	['decimal'] =   11,
	['binary'] =    12,
	['boolean'] =   13,
	['int16_t'] =   14,
	['int32_t'] =   15,
	['int64_t'] =   16,
	['duration'] =  17,
};

local ev_type_index = {
	id_to_name = id_to_name,
	name_to_id = name_to_id
};

return ev_type_index;

