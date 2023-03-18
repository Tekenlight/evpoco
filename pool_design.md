evl_pool: A class that can manage multiple queues, (name, queue_holder*)
	queue_holder: A sub class that can hold a queue of objects

EVLHTTPRequstHandler::_pool (_pool) is a static instance of evl_pool in EVLHTTPRequstHandler class.
queue_holders are added and retrieved from this pool

Upon loading of libevpostgres.dylib and initialization function invoked,
	invokes init_pool_type with "POSTGRESQL", and a local instance of pg_queue_holder (to be used as a template)
		a static global sg_m_o_m is initialized with value of static EVLHTTPRequestHandler::_map_of_maps (std::map<std::string, void*)
		TYPES map is added (if not existing) to sg_m_o_m and returned
			TYPES MAP = (name, queue_holder *)
		If not existing a pg_queue_holder* is created and added to TYPES MAP as ("PSTGRESQL", pg_queue_holder*)
			From now on new queues can be added to queue holder
	with completion of ev_connction (function instance of pg_queue_holder is destroyed with no effect)

Upon addition of new connection to pool by name "127.0.0.1ROC"
	If a queue_holder exists for "127.0.0.1ROC" (in evl_pool) it is picked up
		else a new pg_queue_holder * (clone of pg_queue_holder* in TYPES MAP against "POSTGRESQL") is added in evl_pool
			against "127.0.0.1ROC" and the new instance is picked up
	The connection is added to the queue against "127.0.0.1ROC" in evl_pool

Upon fetching of a new connection from pool by name "127.0.0.1ROC"
	If a queue_holder exists for "127.0.0.1ROC" (in evl_pool) it is picked up
		else a new pg_queue_holder * (clone of pg_queue_holder* in TYPES MAP against "POSTGRESQL") is added in evl_pool
			against "127.0.0.1ROC" and the new instance is picked up
	The connection is dqueued from the queue against "127.0.0.1ROC" and returned


Upon creation of a new SQL statement
	Add statement to Statements map
