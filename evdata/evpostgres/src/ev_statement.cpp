#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evnet/evnet_lua.h"

void add_stmt_id_to_chache(const char * statement, char*p);
const char* get_stmt_id_from_cache(const char * statement);

static int return_finalized_statement(lua_State *L)
{
	PGresult *result = NULL;
	ExecStatusType status;
	char stmt_id[50] = {0};

	char * p = NULL;

	int n = lua_gettop(L);
	if (n != 4) {
		DEBUGPOINT("INVALID PROGRAM STATE\n");
		std::abort();
	}

	connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);

	result = PQgetResult(conn->pg_conn);
	if (!result) {

		lua_pushnil(L);
		lua_pushfstring(L, EV_SQL_ERR_ALLOC_STATEMENT, PQerrorMessage(conn->pg_conn));

		DEBUGPOINT("ret = [2]\n");
		void * new_byte = lua_touserdata(L, 4);
		if (new_byte) free(new_byte);

		return 2;
	}

	status = PQresultStatus(result);
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {

		const char *err_string = PQresultErrorMessage(result);

		lua_pushnil(L);
		lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, err_string);
		PQclear(result);

		DEBUGPOINT("ret = [2]\n");
		void * new_byte = lua_touserdata(L, 4);
		if (new_byte) free(new_byte);

		return 2;
	}

	PQclear(result);

	p = (char*)get_stmt_id_from_cache(luaL_checkstring(L, 3));
	if (!p) {
		p = (char*)lua_touserdata(L, 4);
		//DEBUGPOINT("GOT NEW ID FROM ALLOCATION [%p]\n", p);
		add_stmt_id_to_chache(luaL_checkstring(L, 3), p);
	}
	else {
		//DEBUGPOINT("GOT EXISTING ID FROM CACHE [%p]\n", p);
	}
	lua_settop(L, 3);

	sprintf(stmt_id, "%p", p);
	(*(conn->cached_stmts))[std::string(stmt_id)] = 1;

	statement_t *statement = NULL;
	statement = (statement_t *)lua_newuserdata(L, sizeof(statement_t));
	statement->conn = conn;
	statement->result = NULL;
	statement->tuple = 0;
	statement->name = strdup(stmt_id);
	statement->source = strdup(luaL_checkstring(L, 2));
	luaL_getmetatable(L, EV_POSTGRES_STATEMENT);
	lua_setmetatable(L, -2);
	//DEBUGPOINT("PREPARED STATMENT [%s][%s][%s]\n", statement->name, statement->source, luaL_checkstring(L, 3));

	return 1;
}

static int finalize_statement_creation(lua_State *L, int status, lua_KContext ctx)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);

	char stmt_id[50] = {0};
	int ret = 0;

	Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
	//DEBUGPOINT("SOCKET READY FOR [%d]\n", usN.getConnSockState());
	switch (usN.getConnSockState()) {
		case Poco::evnet::EVUpstreamEventNotification::READY_FOR_READ:
		{
			//DEBUGPOINT("READY FOR READ\n");
			ret = PQconsumeInput(conn->pg_conn);
			if (ret == 0) {
				lua_pushnil(L);
				lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

				DEBUGPOINT("ret = [2]\n");
				void * new_byte = lua_touserdata(L, 4);
				if (new_byte) free(new_byte);

				return 2;
			}
			ret = 0;
			ret = PQisBusy(conn->pg_conn);
			if (ret != 0) {
				DEBUGPOINT("MORE DATA NEEDED FOR READ\n");
				int socket_wait_mode = Poco::evnet::EVLHTTPRequestHandler::READ;
				reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
				return lua_yieldk(L, 0, (lua_KContext)ctx, finalize_statement_creation);
			}
			//DEBUGPOINT("READ COMPLETE\n");
			break;
		}
		case Poco::evnet::EVUpstreamEventNotification::READY_FOR_WRITE:
		case Poco::evnet::EVUpstreamEventNotification::READY_FOR_READWRITE:
		{
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

				DEBUGPOINT("ret = [2]\n");
				void * new_byte = lua_touserdata(L, 4);
				if (new_byte) free(new_byte);

				return 2;
			}

			reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
			return lua_yieldk(L, 0, (lua_KContext)ctx, finalize_statement_creation);
		}
		default:
		{
			lua_pushnil(L);
			lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

			DEBUGPOINT("ret = [2]\n");
			void * new_byte = lua_touserdata(L, 4);
			if (new_byte) free(new_byte);

			return 2;
		}

	}
	//DEBUGPOINT("DONE WITH HANDSHAKE, TIME TO FINALIZE\n");

	return return_finalized_statement(L);

}

static int crete_statement(lua_State *L, const char *sql_stmt)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);


	connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
	char stmt_id[50] = {0};

	char *new_stmt = NULL;

	int n = lua_gettop(L);
	if (n != 3) {
		DEBUGPOINT("INVALID PROGRAM STATE\n");
		std::abort();
	}

	new_stmt = ev_sql_replace_placeholders(L, '$', sql_stmt);
	char* p = (char*)get_stmt_id_from_cache(luaL_checkstring(L, 3));
	if (!p) {
		p = (char*)malloc(sizeof(char));
		//DEBUGPOINT("PUSHING POINTER [%p]\n", p);
		lua_pushlightuserdata(L, p);
	}
	else {
		//DEBUGPOINT("PUSHING NIL\n");
		lua_pushnil(L);
	}
	sprintf(stmt_id, "%p", p);
	/* Here onwards changes */
	int ret = 0;
	ret = PQsetnonblocking(conn->pg_conn, 1);
	if (ret == -1) {
		lua_pushnil(L);
		lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

		DEBUGPOINT("ret = [2]\n");
		void * new_byte = lua_touserdata(L, 4);
		free(new_stmt);
		if (new_byte) free(new_byte);

		return 2;
	}
	ret = 0;

	//DEBUGPOINT("SENDING STATEMENT FOR PREPARE\n");
	ret = PQsendPrepare(conn->pg_conn, stmt_id, new_stmt, 0, NULL);
	free(new_stmt);

	if (ret == 0) {
		lua_pushnil(L);
		lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, PQerrorMessage(conn->pg_conn));

		DEBUGPOINT("ret = [2]\n");
		void * new_byte = lua_touserdata(L, 4);
		if (new_byte) free(new_byte);

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

		DEBUGPOINT("ret = [2]\n");
		void * new_byte = lua_touserdata(L, 4);
		if (new_byte) free(new_byte);

		return 2;
	}

	//DEBUGPOINT("WIATING FOR [%d] ON SOCKET\n", socket_wait_mode);
	reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(conn->pg_conn), socket_wait_mode);
	return lua_yieldk(L, 0, (lua_KContext)0, finalize_statement_creation);
}

int ev_postgres_statement_create(lua_State *L, connection_t *conn, const char *stmt_source, const char *sql_stmt)
{
	int ret = 0;
	char stmt_id[50] = {0};

	statement_t *statement = NULL;

	char* p = (char*)get_stmt_id_from_cache(sql_stmt);
	int cp = 0;
	if (p) {
		sprintf(stmt_id, "%p", p);
		auto it = conn->cached_stmts->find(std::string(stmt_id));
		if (it != conn->cached_stmts->end()) cp = it->second;
	}

	if (!cp) {
		//DEBUGPOINT("DID NOT FIND STATEMT [%p][%s]\n", p, sql_stmt);
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

static int statement_close(lua_State *L) {
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);

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

		DEBUGPOINT("RESULT\n");
		PQclear(statement->result);
		statement->result = NULL;
	}

	if (statement->name) {
		free(statement->name);
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

