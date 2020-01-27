cjson = require('cjson');
mongo = require('mongo');

local client = mongo.Client('mongodb://127.0.0.1');
local db = client:getDatabase('examples');

local envelope = { bsonType = "object",
				required = {__array=true, "data" },
				properties = {
					data = {
						bsonType = "object",
						descripton = "envelope that holds the actual object",
						required = {__array=true, "org_id", "org_name", "ts_cnt"},
						properties = {
							org_id = {
								bsonType = "string",
								description = "must be a string and is required"
							},
							org_name = {
								bsonType = "string",
								description = "must be string and is required"
							},
							ts_cnt = {
								bsonType = "int",
								description = "must be an integer and is required"
							}
						}
					}
				}
			};
local scema = {};
scema["$jsonSchema"] = envelope;
local doc = {};
doc.validator = a2;

bsondoc = mongo.BSON(doc);

b =	' { "validator":  {"$jsonSchema": { "bsonType" : "object", "required" : ["data"], "properties" : {"data": { "bsonType": "object", "description": "envelope that holds the actual object", "required": [ "org_id", "org_name", "ts_cnt"], "properties" : { "org_id" : { "bsonType" : "string", "description" : "must be a string and is required" }, "org_name" : { "bsonType" : "string", "description" : "must be string and is required" }, "ts_cnt" : { "bsonType" : "int", "description" : "must be an integer and is required" } } } } } } } '

bb = mongo.BSON(b);
if (aa == bb) then print("They are same"); end
res = db:createCollection("companies", bb)
print(res);

i = ' { "createIndexes" : "companies", "indexes" : [ { "key": { "data.org_id" : 1 }, "name" : "companies_primary_index", "unique" : true } ] } '


ii = mongo.BSON(i);
--print(ii);

res = client:command("examples", ii);
print(res);
