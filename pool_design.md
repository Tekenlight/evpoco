evl\_pool: A class that can manage multiple queues, (name, queue\_holder\*)
	queue\_holder: A sub class that can hold a queue of objects

EVLHTTPRequstHandler::\_pool (\_pool) is a static instance of evl\_pool in EVLHTTPRequstHandler class.
queue\_holders are added and retrieved from this pool

Upon loading of libevpostgres.dylib and initialization function invoked,
	invokes init\_pool\_type with "POSTGRESQL", and a local instance of pg\_queue\_holder (to be used as a template)
		a static global sg\_m\_o\_m is initialized with value of static EVLHTTPRequestHandler::\_map\_of\_maps (std::map<std::string, void*>)
		TYPES map is added (if not existing) to sg_\m\_o\_m and returned
			TYPES MAP = (name, queue\_holder \*)
		If not existing a pg\_queue\_holder* is created and added to TYPES MAP as ("PSTGRESQL", pg\_queue\_holder\*)
			From now on new queues can be added to queue holder
	with completion of ev\_connction (function instance of pg\_queue\_holder is destroyed with no effect)

Upon addition of new connection to pool by name "127.0.0.1ROC"
	If a queue\_holder exists for "127.0.0.1ROC" (in evl\_pool) it is picked up
		else a new pg\_queue\_holder * (clone of pg\_queue\_holder* in TYPES MAP against "POSTGRESQL") is added in evl\_pool
			against "127.0.0.1ROC" and the new instance is picked up
	The connection is added to the queue against "127.0.0.1ROC" in evl\_pool

Upon fetching of a new connection from pool by name "127.0.0.1ROC"
	If a queue\_holder exists for "127.0.0.1ROC" (in evl\_pool) it is picked up
		else a new pg\_queue\_holder * (clone of pg\_queue\_holder* in TYPES MAP against "POSTGRESQL") is added in evl\_pool
			against "127.0.0.1ROC" and the new instance is picked up
	The connection is dqueued from the queue against "127.0.0.1ROC" and returned


Upon creation of a new SQL statement
	Add statement to Statements map
