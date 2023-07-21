local error_msg_handler = function (msg) 
	local msg_line = msg;
	if (msg_line == nil) then msg_line = ''; end
	local parts_of_msg_line = require "pl.stringx".split(msg_line, ':');
	if (#parts_of_msg_line > 2) then
		local message = require "pl.stringx".strip(parts_of_msg_line[3]);
		local i = 4;
		while (i <= #parts_of_msg_line) do
			message = message ..":".. parts_of_msg_line[i];
			i = i + 1;
		end
	end
	return debug.traceback(msg, 3);
end

local declaredNames = {}

function declare (name, initval)
	rawset(_G, name, initval)
	declaredNames[name] = true
end

function variable_declared(name)
	return (rawget(_G, name) ~= nil);
end

local exception_list = {
	___CACHED_FILE_EXISTS_FUNCTION___ = true,
	___CACHED_PATH_FUNCTION___ = true,
	___FILE_CACHING_FUNCTION___ = true,
	___ADDTO_CACHED_PATH_FUNCTION___ = true,
	unpack = true,
	warn = true,
	message_validation_context = true,
	element_handler_cache = true,
	bigdecimal_init = true,
}

local function in_exception_list(n)
	return (exception_list[n] ~= nil);
end

setmetatable(_G, {
	__newindex = function (t, n, v)
		if (in_exception_list(n)) then
			return rawset(t, n, v);
		end
		if not declaredNames[n] then
			print(debug.traceback("attempt to write to undeclared var. "..n, 3));
			--return rawset(t, n, v);
			error("attempt to write to undeclared var. "..n, 2)
		else
			rawset(t, n, v)   -- do the actual set
		end
	end,
	__index = function (_, n)
		if (in_exception_list(n)) then
			return rawget(_, n);
		end
		if not declaredNames[n] then
			print(debug.traceback("attempt to read undeclared var. "..n, 3));
			--return rawget(_, n);
			error("attempt to read undeclared var. "..n, 2)
		else
			print(debug.traceback("attempt to read undeclared var. "..n, 3));
			return nil
		end
	end,
})





local args = {...};
local s_args = args[1];

local cl_args = {};
if (s_args ~= nil) then
	cl_args = (require "pl.stringx".split(s_args, '<|SEPARATOR|>'))
else
	error("No arguments passed");
end

return table.unpack(cl_args);

