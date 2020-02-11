#!/usr/bin/lua

local _M = {}

-- Driver to module_loader mapping
local name_to_module_loader = {
    mysql = package.loadlib('libevsqlite.so','luaopen_evrdbms_mysql'),
    postgresql = package.loadlib('libevpostgresql.so','luaopen_evrdbms_postgresql'),
    sqlite = package.loadlib('libevsqlite.dylib','luaopen_evrdbms_sqlite3'),
    db2 = package.loadlib('libevdb2.so','luaopen_evrdbms_db2'),
    oracle = package.loadlib('libevoracle.so','luaopen_evrdbms_oracle'),
    odbc = package.loadlib('libevodbc.so','luaopen_evrdbms_odbc'),
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
