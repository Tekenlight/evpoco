--[[
--23-Jan-2020
--
--BIOP mongo db connection_manager.
--Has methods for management fo connections to a mongo db
--
--Author : Sudheer. H. R.
--We will add connection pool logic here later on
--]]
mongo = require('mongo');
local connection_manager = {};

connection_manager.connect = function (db_url, db_schema_name, db_user_id, db_password) -- {
	local client = mongo.Client(db_url);
	db = client:getDatabase(db_schema_name);
	return db;
end -- }

return connection_manager;
