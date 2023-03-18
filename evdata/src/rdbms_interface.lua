#!/usr/bin/lua

local _M = {}

local utils = require('service_utils.common.utils');
-- Driver to module_loader mapping
local name_to_module_loader = {
    mysql = utils.load_library('libevmysql'),
    postgresql = utils.load_library('libevpostgresql'),
    sqlite = utils.load_library('libevsqlite'),
    db2 = utils.load_library('libevdb2'),
    oracle = utils.load_library('libevoracle'),
    odbc = utils.load_library('libevodbc'),
}

local driver_to_initfuncs = {};
for n, l in pairs(name_to_module_loader) do
	if l ~= nil then
		driver_to_initfuncs[n]=l;
	end
end


 -- High level DB connection function
 -- This should be used rather than DBD.{Driver}.New
function _M.Connect(driver, ...)
    local db = driver_to_initfuncs[driver]();

    if db == nil then
		--error(string.format("Driver '%s' not found. Available drivers are: %s", driver, available))
		error(string.format("Driver for '%s' not found", driver))
    end

    return db.New(...)
end

-- List drivers available on this system
function _M.Drivers()
    return driver_to_initfunc;
end


-- Versioning Information
_M._VERSION = '0.01'

return _M
