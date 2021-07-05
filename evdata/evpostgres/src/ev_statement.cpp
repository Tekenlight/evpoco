#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evnet/evnet_lua.h"

void add_stmt_id_to_chache(const char * statement, const char*p);
const char* get_stmt_id_from_cache(const char * statement);

typedef int (*data_return_func)(lua_State *, PGresult *) ;

struct finalize_data_s {
	void * err_mem_to_free;
	int lua_stack_base;
	int bool_or_null;
	data_return_func func_to_return_data;
	connection_t * conn;
};

const char * get_stmt_id(lua_State *L)
{
	const char * p = (const char*)get_stmt_id_from_cache(luaL_checkstring(L, 3));
	if (!p) {
		p = (const char *)lua_touserdata(L, -1);
	}
	return p;
}

static int return_finalized_statement(lua_State *L, PGresult * r)
{
	PGresult * result = r;
	ExecStatusType status;
	char stmt_id[50] = {0};

	connection_t *conn = (connection_t *)luaL_checkudata(L, -4, EV_POSTGRES_CONNECTION);
	const char * source = luaL_checkstring(L, -3);
	const char *stmt = luaL_checkstring(L, -2);
	sprintf(stmt_id, "%p", get_stmt_id(L));
	const char * p = NULL;
	p = (const char*)get_stmt_id_from_cache(luaL_checkstring(L, -2));
	if (!p) {
		p = (const char *)lua_touserdata(L, -1);
		add_stmt_id_to_chache(stmt, p);
	}

	sprintf(stmt_id, "%p", p);
	(*(conn->cached_stmts))[std::string(stmt_id)] = 1;

	PQclear(result);
	statement_t *statement = NULL;
	statement = (statement_t *)lua_newuserdata(L, sizeof(statement_t));
	statement->conn = conn;
	statement->result = NULL;
	statement->tuple = 0;
	statement->name = strdup(stmt_id);
	statement->source = strdup(source);
	luaL_getmetatable(L, EV_POSTGRES_STATEMENT);
	lua_setmetatable(L, -2);
	//DEBUGPOINT("PREPARED STATMENT [%s][%s][%s]\n", statement->name, statement->source, luaL_checkstring(L, 3));

	return 1;
}

static int finalize_statement_processing(lua_State *L, int status, lua_KContext ctx)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	PGresult *result = NULL;

	struct finalize_data_s * fid = (struct finalize_data_s *) ctx;

	connection_t *conn = fid->conn;

	int ret = 0;

	Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
	//DEBUGPOINT("SOCKET READY FOR [%d]\n", usN.getConnSockState());
	switch (usN.getConnSockState()) {
		case Poco::evnet::EVUpstreamEventNotification::READY_FOR_READ: {
			//DEBUGPOINT("READY FOR READ\n");
			ret = PQconsumeInput(conn->pg_conn);
			if (ret == 0) {
				if (!fid->bool_or_null) lua_pushnil(L); else lua_pushboolean(L, 0);
				lua_pushfstring(L, EV_SQL_ERR_PROC, PQerrorMessage(conn->pg_conn));

				DEBUGPOINT("ret = [2]\n");
				if (fid->err_mem_to_free) free(fid->err_mem_to_free);
				conn->conn_in_error = 1;
				free(fid);

				return 2;
			}
			ret = 0;
			ret = PQisBusy(conn->pg_conn);
			if (ret != 0) {
				DEBUGPOINT("MORE DATA NEEDED FOR READ\n");
				int socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READ;
				reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
				return lua_yieldk(L, 0, (lua_KContext)ctx, finalize_statement_processing);
			}
			//DEBUGPOINT("READ COMPLETE ret = [%d]\n", ret);
			break;
		}
		case Poco::evnet::EVUpstreamEventNotification::READY_FOR_WRITE:
		case Poco::evnet::EVUpstreamEventNotification::READY_FOR_READWRITE: {
			ret = PQflush(conn->pg_conn);
			int socket_wait_mode = 0;
			if (ret == 1) {
				//DEBUGPOINT("HAVE TO WAIT FOR READWRITE\n");
				socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READWRITE;
			}
			else if (ret == 0) {
				//DEBUGPOINT("HAVE TO WAIT FOR READ\n");
				socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READ;
			}
			else {
				if (!fid->bool_or_null) lua_pushnil(L); else lua_pushboolean(L, 0);
				lua_pushfstring(L, EV_SQL_ERR_PROC, PQerrorMessage(conn->pg_conn));

				DEBUGPOINT("ret = [2]\n");
				if (fid->err_mem_to_free) free(fid->err_mem_to_free);
				conn->conn_in_error = 1;
				free(fid);

				return 2;
			}

			reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
			return lua_yieldk(L, 0, (lua_KContext)ctx, finalize_statement_processing);
		}
		default: {
			if (!fid->bool_or_null) lua_pushnil(L); else lua_pushboolean(L, 0);
			lua_pushfstring(L, EV_SQL_ERR_PROC, PQerrorMessage(conn->pg_conn));

			DEBUGPOINT("ret = [2]\n");
			if (fid->err_mem_to_free) free(fid->err_mem_to_free);
			conn->conn_in_error = 1;
			free(fid);

			return 2;
		}

	}
	//DEBUGPOINT("DONE WITH HANDSHAKE, TIME TO FINALIZE isbusy=[%d]\n", ret);
	result = PQgetResult(conn->pg_conn);
	if (!result) {

		if (!fid->bool_or_null) lua_pushnil(L); else lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_ALLOC, PQerrorMessage(conn->pg_conn));

		DEBUGPOINT("ret = [2]\n");
		if (fid->err_mem_to_free) free(fid->err_mem_to_free);
		conn->conn_in_error = 1;
		free(fid);

		return 2;
	}
	PGresult *result1 = NULL;
	while ((result1 = PQgetResult(conn->pg_conn)) != NULL) {
		DEBUGPOINT("THIS SHOULD NEVER GET EXECUTED\n");
		DEBUGPOINT("SINCE WE ARE FIRING ONLY ONE COMMAND AT A TIME AND WAITING FOR RESULT\n");
		std::abort();
		result = result1;
	}

	status = PQresultStatus(result);
	//DEBUGPOINT("RESULT = [%d]\n", status);
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {

		const char *err_string = PQresultErrorMessage(result);

		if (!fid->bool_or_null) lua_pushnil(L); else lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_PROC, err_string);
		DEBUGPOINT(EV_SQL_ERR_PROC, err_string);
		PQclear(result);

		DEBUGPOINT("ret = [2]\n");
		if (fid->err_mem_to_free) free(fid->err_mem_to_free);
		conn->conn_in_error = 1;
		free(fid);

		return 2;
	}
	//PQclear(result);

	data_return_func f = fid->func_to_return_data;
	free(fid);
	return f(L, result);
}

static int crete_statement(lua_State *L, const char *sql_stmt)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	connection_t *conn = (connection_t *)luaL_checkudata(L, -3, EV_POSTGRES_CONNECTION);
	char stmt_id[50] = {0};

	char *new_stmt = NULL;

	new_stmt = ev_sql_replace_placeholders(L, '$', sql_stmt);
	const char *p = (const char*)get_stmt_id_from_cache(luaL_checkstring(L, -1));
	if (!p) {
		//DEBUGPOINT("NOT CACHED\n");
		p = (const char*)malloc(sizeof(char));
		lua_pushlightuserdata(L, (void*)p);
	}
	else {
		//DEBUGPOINT("CACHED\n");
		lua_pushnil(L);
	}
	sprintf(stmt_id, "%p", p);
	//DEBUGPOINT("STMT_ID [%s] \n", stmt_id);
	/* Here onwards changes */
	int ret = 0;

	//DEBUGPOINT("SENDING STATEMENT FOR PREPARE\n");
	ret = PQsendPrepare(conn->pg_conn, stmt_id, new_stmt, 0, NULL);
	free(new_stmt);

	if (ret == 0) {
		lua_pushnil(L);
		lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));
		DEBUGPOINT(EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

		DEBUGPOINT("stmt_id = [%s][%s]\n", stmt_id, PQerrorMessage(conn->pg_conn));
		DEBUGPOINT("CONN STATUS [%d]\n", PQstatus(conn->pg_conn));
		void * new_byte = lua_touserdata(L, 4);
		if (new_byte) free(new_byte);
		conn->conn_in_error = 1;

		return 2;
	}

	ret = 0;

	ret = PQflush(conn->pg_conn);

	int socket_wait_mode = 0;
	if (ret == 1) {
		//DEBUGPOINT("HAVE TO WAIT FOR READWRITE\n");
		socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READWRITE;
	}
	else if (ret == 0) {
		//DEBUGPOINT("HAVE TO WAIT FOR READ\n");
		socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READ;
	}
	else {
		lua_pushnil(L);
		lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

		//DEBUGPOINT("ret = [2]\n");
		void * new_byte = lua_touserdata(L, 4);
		if (new_byte) free(new_byte);
		conn->conn_in_error = 1;

		return 2;
	}

	//DEBUGPOINT("WIATING FOR [%d] ON SOCKET\n", socket_wait_mode);
	struct finalize_data_s * fid = (struct finalize_data_s *)malloc(sizeof(struct finalize_data_s));;
	memset(fid, 0, sizeof(struct finalize_data_s));
	fid->conn = conn;
	fid->err_mem_to_free = lua_touserdata(L, 4);
	fid->lua_stack_base = lua_gettop(L);
	fid->bool_or_null = 0;
	fid->func_to_return_data = return_finalized_statement;
	reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
	return lua_yieldk(L, 0, (lua_KContext)fid, finalize_statement_processing);
}

int ev_postgres_statement_create(lua_State *L, connection_t *conn, const char *stmt_source, const char *sql_stmt)
{
	int ret = 0;
	char stmt_id[50] = {0};

	statement_t *statement = NULL;

	const char* p = get_stmt_id_from_cache(sql_stmt);
	int cp = 0;
	if (p) {
		sprintf(stmt_id, "%p", p);
		//DEBUGPOINT("STMT_ID [%s]\n", stmt_id);
		auto it = conn->cached_stmts->find(std::string(stmt_id));
		if (it != conn->cached_stmts->end()) cp = it->second;
		//DEBUGPOINT("STMT_ID [%s] cp[%d]\n", stmt_id, cp);
	}
	//DEBUGPOINT("STMT_ID [%s] cp[%d]\n", stmt_id, cp);

	if (!cp) {
		/*
		 * convert SQL string into a PSQL API compatible SQL statement
		 * should free converted statement after use
		 */ 
		return crete_statement(L, sql_stmt);
	}
	else {
		//DEBUGPOINT("RETRIEVED stmt[%p] [%s] from cache\n", p, sql_stmt);
		ret = 1;

		statement = (statement_t *)lua_newuserdata(L, sizeof(statement_t));
		statement->conn = conn;
		statement->result = NULL;
		statement->tuple = 0;
		statement->name = strdup(stmt_id);
		statement->source = strdup(stmt_source);
		luaL_getmetatable(L, EV_POSTGRES_STATEMENT);
		lua_setmetatable(L, -2);
	}

	return ret;
}

static int return_data_from_stmt_execution(lua_State *L, PGresult *result)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);
	ExecStatusType status = PQresultStatus(result);
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
		if (!result) PQclear(result);
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_BINDING_EXEC, PQresultErrorMessage(result));
		DEBUGPOINT(EV_SQL_ERR_BINDING_EXEC, PQresultErrorMessage(result));
		statement->conn->conn_in_error = 1;
		return 2;
	}

	if (statement->result) {
		status = PQresultStatus (statement->result);
		if (status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK) {
			PQclear (statement->result);
		}
	}
	statement->result = result;
	//DEBUGPOINT("STMT EXEC DONE\n");

	lua_pushboolean(L, 1);
	return 1;
}

static int bind_error(lua_State *L, char * err, int type, statement_t *statement)
{
	snprintf(err, sizeof(err)-1, EV_SQL_ERR_BINDING_TYPE_ERR, lua_typename(L, type));
	lua_pushboolean(L, 0);
	lua_pushfstring(L, EV_SQL_ERR_BINDING_PARAMS, err);
	DEBUGPOINT(EV_SQL_ERR_BINDING_PARAMS, err);
	statement->conn->conn_in_error = 1;
	return 2;
}

static int ev_statement_execute(lua_State *L)
{
	int n = lua_gettop(L);
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);
	int num_bind_params = n - 1;   
	ExecStatusType status;
	int p;

	const char **params;
	int *param_lengths;
	int *param_formats;
	PGresult *result = NULL;

	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	connection_t *conn = statement->conn;


	/*
	 * Sanity check - is database still connected?
	 */
	if (PQstatus(statement->conn->pg_conn) != CONNECTION_OK) {
		lua_pushstring(L, EV_SQL_ERR_STATEMENT_BROKEN);
		DEBUGPOINT(EV_SQL_ERR_STATEMENT_BROKEN);
		conn->conn_in_error = 1;
		lua_error(L);	
	}


	statement->tuple = 0;

	params = (const char **)malloc(num_bind_params * sizeof(const char *));
	memset(params, 0, num_bind_params * sizeof(const char *));

	param_lengths = (int *)malloc(num_bind_params * (sizeof(int)));
	memset((void*)param_lengths, 0, (num_bind_params * (sizeof(int))));

	param_formats = (int *)malloc(num_bind_params * (sizeof(int)));
	memset((void*)param_formats, 0, num_bind_params * (sizeof(int)));

	/*
	 * convert and copy parameters into a string array
	 */ 
	for (p = 2; p <= n; p++) {
		int i = p - 2;	
		int type = lua_type(L, p);
		char err[64];
		memset(&err, 0, 64);

		switch(type) {
			case LUA_TNIL:
				params[i] = NULL;
				param_lengths[i] = 0;
				param_formats[i] = 0;
				break;
			case LUA_TBOOLEAN:
				/*
				 * boolean values in pg_conn can either be
				 * t/f or 1/0. Pass integer values rather than
				 * strings to maintain semantic compatibility
				 * with other EV_SQL drivers that pass booleans
				 * as integers.
				 */
				params[i] = lua_toboolean(L, p) ?  "1" : "0";
				param_lengths[i] = strlen(params[i]);
				param_formats[i] = 0;
				break;
			case LUA_TNUMBER:
			case LUA_TSTRING:
				params[i] = lua_tostring(L, p);
				param_lengths[i] = strlen(params[i]);
				param_formats[i] = 0;
				break;
			case LUA_TTABLE: {
				lua_getfield (L, p, "size");
				if (!lua_isinteger(L, -1)) {
					free(params);
					return bind_error(L, err, type, statement);
				}
				int size = lua_tointeger(L, -1);
				if (size <0) {
					free(params);
					return bind_error(L, err, type, statement);
				}
				lua_settop(L, n);

				lua_getfield(L, p, "value");
				if (!lua_isuserdata(L, -1)) {
					free(params);
					return bind_error(L, err, type, statement);
				}
				void * value = lua_touserdata(L, -1);
				lua_settop(L, n);

				params[i] = (const char*)value;
				param_lengths[i] = size;
				param_formats[i] = 1;

				break;
			}
			default:
				free(params);
				return bind_error(L, err, type, statement);
		}
	}

	//DEBUGPOINT("STMT NAME = [%s]\n", statement->name);
	int ret = 0;
	ret = PQsendQueryPrepared(
		statement->conn->pg_conn,
		statement->name,
		num_bind_params,
		(const char **)params,
		(const int *)param_lengths,
		(const int *)param_formats,
		0
	);
	free(params);
	free(param_lengths);

	if (ret != 1) {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_EXECUTE_FAILED, PQerrorMessage(conn->pg_conn));
		DEBUGPOINT(EV_SQL_ERR_EXECUTE_FAILED, PQerrorMessage(conn->pg_conn));

		DEBUGPOINT("CONN STATUS [%d]\n", PQstatus(conn->pg_conn));
		conn->conn_in_error = 1;

		return 2;
	}

	ret = 0;
	ret = PQflush(conn->pg_conn);

	int socket_wait_mode = 0;
	if (ret == 1) {
		//DEBUGPOINT("HAVE TO WAIT FOR READWRITE\n");
		socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READWRITE;
	}
	else if (ret == 0) {
		//DEBUGPOINT("HAVE TO WAIT FOR READ\n");
		socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READ;
	}
	else {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));
		DEBUGPOINT(EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

		conn->conn_in_error = 1;

		return 2;
	}

	//DEBUGPOINT("WIATING FOR [%d] ON SOCKET\n", socket_wait_mode);
	
	struct finalize_data_s * fid = (struct finalize_data_s *)malloc(sizeof(struct finalize_data_s));;
	memset(fid, 0, sizeof(struct finalize_data_s));
	fid->conn = conn;
	fid->err_mem_to_free = NULL;
	fid->lua_stack_base = lua_gettop(L);
	fid->bool_or_null = 1;
	fid->func_to_return_data = return_data_from_stmt_execution;
	reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
	return lua_yieldk(L, 0, (lua_KContext)fid, finalize_statement_processing);

}

static int deallocate(statement_t *statement)
{
	PGresult *result;
	ExecStatusType status;

	/*
	 * It's possible to get here with a closed database handle
	 * - either by a mistake by the calling Lua program, or by
	 * garbage collection. Don't die in that case.
	 */
	if (statement->conn->pg_conn) {
		//snprintf(command, IDLEN+13, "DEALLOCATE \"%s\"", statement->name);    
		std::string command = std::string("DEALLOCATE \"") + statement->name + std::string("\"");
		result = PQexec(statement->conn->pg_conn, command.c_str());

		if (!result)
			return 1;

		status = PQresultStatus(result);
		PQclear(result);

		if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
			return 1;
	}

	return 0;
}

/*
 * num_rows = statement:rowcount()
 */
static int statement_rowcount(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);

	if (!statement->result) {
		luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
	}

	lua_pushinteger(L, PQntuples(statement->result));

	return 1;
}

/*
 * column_names = statement:columns()
 */
static int statement_columns(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);

	int i;
	int num_columns;
	int d = 1;

	if (!statement->result) {
		luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
		return 0;
	}

	num_columns = PQnfields(statement->result);
	lua_newtable(L);
	for (i = 0; i < num_columns; i++) {
		const char *name = PQfname(statement->result, i);

		LUA_PUSH_ARRAY_STRING(d, name);
	}

	return 1;
}

/*
 * num_affected_rows = statement:affected()
 */
static int statement_affected(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);

	if (!statement->result) {
		luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
	}

	lua_pushinteger(L, atoi(PQcmdTuples(statement->result)));

	return 1;
}

static lua_push_type_t postgresql_to_lua_push(unsigned int postgresql_type)
{
	lua_push_type_t lua_type;

	switch(postgresql_type) {
		case INT2OID:
		case INT4OID:
		case INT8OID:
			lua_type =  LUA_PUSH_INTEGER;
			break;

		case FLOAT4OID:
		case FLOAT8OID:
		case DECIMALOID:
			lua_type = LUA_PUSH_NUMBER;
			break;

		case BOOLOID:
			lua_type = LUA_PUSH_BOOLEAN;
			break;

		default:
			lua_type = LUA_PUSH_STRING;
	}

	return lua_type;
}

/*
 * can only be called after an execute
 */
static int statement_fetch_impl(lua_State *L, statement_t *statement, int named_columns)
{
	int tuple = statement->tuple++;
	int i;
	int num_columns;
	int d = 1;

	if (!statement->result) {
		luaL_error(L, EV_SQL_ERR_FETCH_INVALID);
		return 0;
	}

	if (PQresultStatus(statement->result) != PGRES_TUPLES_OK) {
		lua_pushnil(L);
		return 1;
	}

	if (tuple >= PQntuples(statement->result)) {
		lua_pushnil(L);  /* no more results */
		return 1;
	}

	num_columns = PQnfields(statement->result);
	lua_newtable(L);
	for (i = 0; i < num_columns; i++) {
		const char *name = PQfname(statement->result, i);

		if (PQgetisnull(statement->result, tuple, i)) {
			if (named_columns) {
				LUA_PUSH_ATTRIB_NIL(name);
			} else {
				LUA_PUSH_ARRAY_NIL(d);
			}	    
		} else {
			const char *value = PQgetvalue(statement->result, tuple, i);
			lua_push_type_t lua_push = postgresql_to_lua_push(PQftype(statement->result, i));

			/*
			 * data is returned as strings from PSQL
			 * convert them here into Lua types
			 */ 

			if (lua_push == LUA_PUSH_NIL) {
				if (named_columns) {
					LUA_PUSH_ATTRIB_NIL(name);
				} else {
					LUA_PUSH_ARRAY_NIL(d);
				}
			} else if (lua_push == LUA_PUSH_INTEGER) {
				int val = atoi(value);

				if (named_columns) {
					LUA_PUSH_ATTRIB_INT(name, val);
				} else {
					LUA_PUSH_ARRAY_INT(d, val);
				}
			} else if (lua_push == LUA_PUSH_NUMBER) {
				double val = strtod(value, NULL);

				if (named_columns) {
					LUA_PUSH_ATTRIB_FLOAT(name, val);
				} else {
					LUA_PUSH_ARRAY_FLOAT(d, val);
				}
			} else if (lua_push == LUA_PUSH_STRING) {
				if (named_columns) {
					LUA_PUSH_ATTRIB_STRING(name, value);
				} else {
					LUA_PUSH_ARRAY_STRING(d, value);
				}
			} else if (lua_push == LUA_PUSH_BOOLEAN) {
				/* 
				 * booleans are returned as a string
				 * either 't' or 'f'
				 */
				int val = value[0] == 't' ? 1 : 0;

				if (named_columns) {
					LUA_PUSH_ATTRIB_BOOL(name, val);
				} else {
					LUA_PUSH_ARRAY_BOOL(d, val);
				}
			} else {
				luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
			}
		}
	}

	return 1;    
}

static int next_iterator(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, lua_upvalueindex(1), EV_POSTGRES_STATEMENT);
	int named_columns = lua_toboolean(L, lua_upvalueindex(2));

	return statement_fetch_impl(L, statement, named_columns);
}

/*
 * table = statement:fetch(named_indexes)
 */
static int statement_fetch(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);
	int named_columns = lua_toboolean(L, 2);

	return statement_fetch_impl(L, statement, named_columns);
}

/*
 * iterfunc = statement:rows(named_indexes)
 */
static int statement_rows(lua_State *L)
{
	if (lua_gettop(L) == 1) {
		lua_pushvalue(L, 1);
		lua_pushboolean(L, 0);
	} else {
		lua_pushvalue(L, 1);
		lua_pushboolean(L, lua_toboolean(L, 2));
	}

	lua_pushcclosure(L, next_iterator, 2);
	return 1;
}

static int statement_close(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);

	//DEBUGPOINT(" CLOSING STATEMENT\n");
	if (statement->result) {
		/*
		 * Deallocate prepared statement on the
		 * server side
		 */ 
		//deallocate(statement); 
		/*
		 * Allow the statement to remain cached
		 * With a consistent naming schemd for statements
		 * we can reuse the prepared statements.
		 */

		PQclear(statement->result);
		statement->result = NULL;
	}

	if (statement->name) {
		free(statement->name);
	}
	if (statement->source) {
		free(statement->source);
	}

	return 0;    
}

static int new_statement_gc(lua_State *L)
{
	/* always free the handle */
	statement_close(L);

	return 0;
}

/*
 * __tostring
 */
static int statement_tostring(lua_State *L)
{
    void *statement = (void *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);
    lua_pushfstring(L, "%s:%p", EV_POSTGRES_STATEMENT, statement);
    return 1;
}

extern "C" int ev_postgres_statement(lua_State *L);
int ev_postgres_statement(lua_State *L)
{
    static const luaL_Reg statement_methods[] = {
		{"__gc", new_statement_gc},
		{"__tostring", statement_tostring},
        {"affected", statement_affected},
        {"close", statement_close},
        {"columns", statement_columns},
        {"rowcount", statement_rowcount},
        {"fetch", statement_fetch},
        {"execute", ev_statement_execute},
        {"rows", statement_rows},
		{NULL, NULL}
    };

	int n = lua_gettop(L);
	luaL_newmetatable(L, EV_POSTGRES_STATEMENT);
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);
	luaL_setfuncs(L, statement_methods, 0);
	lua_settop(L, n);

    return 0;    
}

