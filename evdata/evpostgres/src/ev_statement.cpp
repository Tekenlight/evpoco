#include <arpa/inet.h>
#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evdata/evpostgres/ev_typeutils.h"
#include "Poco/evnet/evnet_lua.h"

int pqt_get_numeric(char **str, PGresult *result, const char *value);
int pqt_put_numeric(short ** out_buf, char * str);
interval_p_type pqt_get_interval(PGresult *result, const char *value);
const char * pqt_put_interval(const char * in);

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


union u_float {
	float f;
	uint32_t ui32;
};

union u_double {
	double d;
	uint64_t ui64;
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
				//DEBUGPOINT("MORE DATA NEEDED FOR READ\n");
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
		DEBUGPOINT("RESULT = [%d]\n", status);

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
	//if (PQcmdTuples(result))
		//DEBUGPOINT("STMT EXEC DONE %s %d\n", PQcmdTuples(result), PQntuples(result));

	lua_pushboolean(L, 1);
	return 1;
}

static int bind_error(lua_State *L, char * err, int type, statement_t *statement, size_t len)
{
	snprintf(err, len, EV_SQL_ERR_BINDING_TYPE_ERR, lua_typename(L, type));
	lua_pushboolean(L, 0);
	lua_pushfstring(L, EV_SQL_ERR_BINDING_PARAMS, err);
	DEBUGPOINT(EV_SQL_ERR_BINDING_PARAMS, err);
	statement->conn->conn_in_error = 1;
	return 2;
}

#define FREE_PARAMS(p, a, n, l, f) {\
	for (int i = 0; i<n; i++) { \
		if (a[i]) free((void*)p[i]); \
	}\
	free(p); \
	free(a); \
	free(l); \
	free(f); \
}


static int set_stmt_params(lua_State *L, const char ** params, int *param_lengths, int *param_formats, int8_t *allocs, int li, int i)
{
	lua_bind_var_p_type var = (lua_bind_var_p_type)lua_touserdata(L, li);
	//DEBUGPOINT("type = [%d]\n", var->type);
	switch (var->type) {
		case ev_lua_date:
			{
				int32_t * ip = (int32_t*)malloc(sizeof(int32_t));
				*ip = *(int32_t*)(var->val) - (POSTGRES_EPOCH_JDATE - DU_EPOCH_JDATE);
				//DEBUGPOINT("DATE = [%d]\n", *ip);
				*ip = (int32_t)htonl(*ip);
				params[i] = (const char*)ip;
				allocs[i] = 1;
				param_lengths[i] = sizeof(int32_t);
				param_formats[i] = 1;
			}
			break;
		case ev_lua_datetime:
			{
				int64_t * ip = (int64_t*)malloc(sizeof(int64_t));
				*ip = *(int64_t*)(var->val) - ((POSTGRES_EPOCH_JDATE - DU_EPOCH_JDATE) * USECS_PER_DAY);
				*ip = (int64_t)htonll(*ip);
				//DEBUGPOINT("TIMESTAMP = [%lld]\n", *ip);
				params[i] = (const char*)ip;
				allocs[i] = 1;
				param_lengths[i] = sizeof(int64_t);
				param_formats[i] = 1;
			}
			break;
		case ev_lua_time:
			{
				int64_t * ip = (int64_t*)malloc(sizeof(int64_t));
				*ip = (int64_t)htonll(*(int64_t*)(var->val));
				//DEBUGPOINT("TIME = [%lld]\n", *ip);
				params[i] = (const char *)ip;
				allocs[i] = 1;
				param_lengths[i] = sizeof(int64_t);
				param_formats[i] = 1;
			}
			break;
		case ev_lua_duration:
			//DEBUGPOINT("INTERVAL = [%s]\n", (const char *)(var->val));
			params[i] = (const char *)pqt_put_interval((const char *)(var->val));
			if (params[i] == NULL) {
				DEBUGPOINT("type = [%d]\n", var->type);
				return -1;
			}
			allocs[i] = 1;
			param_lengths[i] = sizeof(interval_s_type);
			param_formats[i] = 1;
			break;
		case ev_lua_decimal:
			//DEBUGPOINT("NUMERIC VALUE INPUT = [%s]\n", (const char*)(var->val));
			params[i] = (const char*)(var->val);
			allocs[i] = 0;
			param_lengths[i] = var->size;
			param_formats[i] = 0;
			//DEBUGPOINT("[%d]REACHED HERE, %s\n", i, params[i]);
			break;
		case ev_lua_binary:
			params[i] = (const char*)(var->val);
			allocs[i] = 0;
			param_lengths[i] = var->size;
			param_formats[i] = 1;
			/*
			{
			unsigned char * p = (unsigned char *)(var->val);
			DEBUGPOINT("[%d]REACHED HERE, %p\n", i, p);
			}
			*/
			break;
		case ev_lua_int16_t:
			params[i] = (const char*)malloc(sizeof(int16_t));
			*(uint16_t*)params[i] = (int16_t)htons(*(uint16_t*)(var->val));
			allocs[i] = 1;
			param_lengths[i] = sizeof(int16_t);
			param_formats[i] = 1;
			/*
			{
			int16_t r = ntohs(*(int16_t*)params[i]);
			DEBUGPOINT("[%d]REACHED HERE, %hd %hd\n", i, *((int16_t*)(var->val)), r);
			}
			*/
			break;
		case ev_lua_float:
			{
				union u_float uf;
				uf.f = *(float*)(var->val);
				//DEBUGPOINT("[%d]REACHED HERE, %d %f\n", i, *((int*)(var->val)), uf.f);
				uf.ui32 = htonl(uf.ui32);
				params[i] = (const char*)malloc(sizeof(float));
				*(float*)params[i] = uf.f;
				allocs[i] = 1;
				param_lengths[i] = sizeof(float);
				param_formats[i] = 1;
			}
			break;
		case ev_lua_int32_t:
			params[i] = (const char*)malloc(sizeof(int32_t));
			*(uint32_t*)params[i] = (int32_t)htonl(*(uint32_t*)(var->val));
			allocs[i] = 1;
			param_lengths[i] = sizeof(int32_t);
			param_formats[i] = 1;
			/*
			{
			int r = ntohl(*(int*)params[i]);
			DEBUGPOINT("[%d]REACHED HERE, %d %d\n", i, *((int*)(var->val)), r);
			}
			*/
			break;
		case ev_lua_int64_t:
			params[i] = (const char*)malloc(sizeof(int64_t));
			//DEBUGPOINT("LONG = [%lld]\n", *(int64_t*)(var->val));
			*(uint64_t*)params[i] = (int64_t)htonll(*(uint64_t*)(var->val));
			allocs[i] = 1;
			param_lengths[i] = sizeof(int64_t);
			param_formats[i] = 1;
			/*
			{
			int64_t r = ntohll(*(int64_t*)params[i]);
			DEBUGPOINT("[%d]REACHED HERE, %lld %lld\n", i, *((int64_t*)(var->val)), r);
			}
			*/
			break;
		case ev_lua_nullptr:
			//DEBUGPOINT("[%d]NULL INPUT\n", i);
			params[i] = (const char*)0;
			allocs[i] = 0;
			param_lengths[i] = 0;
			param_formats[i] = 1;
			break;
		default: /* Other types are not supported by PostgreSQL */
			DEBUGPOINT("type = [%d]\n", var->type);
			return -1;
	}
	return 1;
}

static int ev_statement_execute(lua_State *L)
{
	int n = lua_gettop(L);
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);
	int num_bind_params = n - 1;   
	ExecStatusType status;
	int p;

	int8_t *allocs;
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

	allocs = (int8_t*)malloc(num_bind_params * (sizeof(int8_t)));
	memset(allocs, 0, num_bind_params * (sizeof(int8_t)));

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

		//DEBUGPOINT("Here [%d]\n", type);

		switch(type) {
			case LUA_TBOOLEAN:
				/*
				 * boolean values in pg_conn can either be
				 * t/f or 1/0. Pass integer values rather than
				 * strings to maintain semantic compatibility
				 * with other EV_SQL drivers that pass booleans
				 * as integers.
				 */
				params[i] = (const char*)malloc(sizeof(uint8_t));
				*(uint8_t*)params[i] = lua_toboolean(L, p) ?  1 : 0;
				allocs[i] = 1;
				param_lengths[i] = sizeof(uint8_t);
				param_formats[i] = 1;
				//DEBUGPOINT("[%d]%d, %d\n", i, lua_toboolean(L, p), *(uint8_t*)params[i]);
				break;
			case LUA_TNUMBER:
				poco_assert(sizeof(lua_Number) == sizeof(double));
				{
					union u_double ud ;
					ud.d = lua_tonumber(L, p);
					params[i] = (char*)malloc(sizeof(double));
					*(uint64_t*)params[i] = htonll(ud.ui64);
					allocs[i] = 1;
					param_lengths[i] = sizeof(double);
					param_formats[i] = 1;

					/*
					ud.ui64 = ntohll(*((uint64_t*)params[i]));
					DEBUGPOINT("[%d]%lf, %lf\n", i, lua_tonumber(L, p), ud.d);
					*/
				}
				break;
			case LUA_TSTRING:
				//DEBUGPOINT("[%d] %s\n", i, lua_tostring(L, p));
				params[i] = lua_tostring(L, p);
				allocs[i] = 0;
				param_lengths[i] = strlen(params[i]);
				param_formats[i] = 0;
				break;
			case LUA_TUSERDATA:
			case LUA_TLIGHTUSERDATA:
				//DEBUGPOINT("[%d]REACHED HERE\n", i);
				if (-1 == set_stmt_params(L, params, param_lengths, param_formats, allocs,  p, i)) {
					DEBUGPOINT("[%d]REACHED HERE\n", i);
					FREE_PARAMS(params, allocs, num_bind_params, param_lengths, param_formats);
					return bind_error(L, err, type, statement, sizeof(err) -1);
				}
				break;
			default:
				DEBUGPOINT("[%d]REACHED HERE\n", i);
				FREE_PARAMS(params, allocs, num_bind_params, param_lengths, param_formats);
				return bind_error(L, err, type, statement, sizeof(err) -1);
		}
	}

	//DEBUGPOINT("STMT NAME = [%s]\n", statement->name);
	/*
	*/
	int ret = 0;
	ret = PQsendQueryPrepared(
		statement->conn->pg_conn,
		statement->name,
		num_bind_params,
		(const char **)params,
		(const int *)param_lengths,
		(const int *)param_formats,
		1
	);
	FREE_PARAMS(params, allocs, num_bind_params, param_lengths, param_formats);

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
			switch (PQftype(statement->result, i)) {
				case INT2OID:
					{
						short val = 0;
						val = (short)ntohs(*(uint16_t*)(value));

						if (named_columns) {
							LUA_PUSH_ATTRIB_INT(name, val);
						} else {
							LUA_PUSH_ARRAY_INT(d, val);
						}
					}
					break;
				case INT4OID:
					{
						int val = 0;
						val = (short)ntohl(*(uint32_t*)(value));

						if (named_columns) {
							LUA_PUSH_ATTRIB_INT(name, val);
						} else {
							LUA_PUSH_ARRAY_INT(d, val);
						}
					}
					break;
				case INT8OID:
					{
						long val = 0;
						val = ntohll(*(uint64_t*)(value));

						if (named_columns) {
							LUA_PUSH_ATTRIB_INT(name, val);
						} else {
							LUA_PUSH_ARRAY_INT(d, val);
						}
					}
					break;
				case FLOAT4OID:
					{
						union u_float uf;
						uf.ui32 = (uint32_t)0;
						uf.ui32 = ntohl(*(uint32_t*)(value));

						if (named_columns) {
							LUA_PUSH_ATTRIB_FLOAT(name, uf.f);
						} else {
							LUA_PUSH_ARRAY_FLOAT(d, uf.f);
						}
					}
					break;
				case FLOAT8OID:
					{
						union u_double ud;
						ud.ui64 = (uint64_t)0;
						ud.ui64 = ntohll(*(uint64_t*)(value));

						if (named_columns) {
							LUA_PUSH_ATTRIB_FLOAT(name, ud.d);
						} else {
							LUA_PUSH_ARRAY_FLOAT(d, ud.d);
						}
					}
					break;
				case DECIMALOID:
					{
						char * str = NULL;
						int ret = pqt_get_numeric(&str, statement->result, value);
						if (ret == -1) {
							luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
							return 0;
						}

						if (named_columns) {
							//LUA_PUSH_ATTRIB_FLOAT(name, val);
							LUA_PUSH_ATTRIB_STRING(name, str);
						} else {
							//LUA_PUSH_ARRAY_FLOAT(d, val);
							LUA_PUSH_ARRAY_STRING(d, str);
						}
					}
					break;
				case BOOLOID:
					{
						unsigned char val = *value != 0 ? 1 : 0;

						if (named_columns) {
							LUA_PUSH_ATTRIB_BOOL(name, val);
						} else {
							LUA_PUSH_ARRAY_BOOL(d, val);
						}
					}
				default:
					luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
			}
		}
	}

	return 1;    
}

/*
 * can only be called after an execute
 */
static int raw_statement_fetch_impl(lua_State *L, statement_t *statement)
{
	int tuple = statement->tuple++;
	int i;
	int num_columns;
	int d = 1;
	struct lua_bind_variable_s * result_columns = NULL;;

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
	result_columns = (struct lua_bind_variable_s*) malloc(num_columns*sizeof(struct lua_bind_variable_s));
	memset(result_columns, 0, num_columns * sizeof(struct lua_bind_variable_s));

	lua_newtable(L);
	for (i = 0; i < num_columns; i++) {
		const char *name = PQfname(statement->result, i);

		if (PQgetisnull(statement->result, tuple, i)) {
			result_columns[i].name = name;
			result_columns[i].type = ev_lua_nullptr;
			result_columns[i].val = NULL;
			result_columns[i].size = 0;
			LUA_PUSH_ARRAY_NIL(d);
		} else {
			const char *value = PQgetvalue(statement->result, tuple, i);
			int length = PQgetlength(statement->result, tuple, i);
			//DEBUGPOINT(" index [%d] column # [%d] type [%d]\n", d, i, PQftype(statement->result, i));
			switch (PQftype(statement->result, i)) {
				case INT2OID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_int16_t;
						*(int16_t*)value = ntohs(*((int16_t*)value));
						result_columns[i].val = (void*)value;;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case INT4OID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_int32_t;
						*(int32_t*)value = ntohl(*((int32_t*)value));
						result_columns[i].val = (void*)value;;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case INT8OID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_int64_t;
						*(int64_t*)value = ntohll(*((int64_t*)value));
						result_columns[i].val = (void*)value;;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case FLOAT4OID:
					{
						union u_float uf;
						uf.ui32 = (uint32_t)0;
						uf.ui32 = ntohl(*(uint32_t*)(value));
						*(float *)value = uf.f;

						result_columns[i].name = name;
						result_columns[i].type = ev_lua_float;
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_FLOAT(d, uf.f);
					}
					break;
				case FLOAT8OID:
					{
						union u_double ud;
						ud.ui64 = (uint64_t)0;
						ud.ui64 = ntohll(*(uint64_t*)(value));
						*(double *)value = ud.d;

						result_columns[i].name = name;
						result_columns[i].type = ev_lua_number;
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_FLOAT(d, ud.d);
					}
					break;
				case DECIMALOID:
					{
						char * str = NULL;
						int ret = pqt_get_numeric(&str, statement->result, value);
						//DEBUGPOINT("NUMERIC VALUE READ = [%s]\n", str);
						if (ret == -1) {
							luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
							return 0;
						}

						result_columns[i].name = name;
						result_columns[i].type = ev_lua_decimal;
						result_columns[i].val = (void *)str;
						result_columns[i].size = strlen(str);
						LUA_PUSH_ARRAY_STRING(d, str);
					}
					break;
				case BOOLOID:
					{
						unsigned char val = *value != 0 ? 1 : 0;

						result_columns[i].name = name;
						result_columns[i].type = ev_lua_boolean;
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_BOOL(d, val);
					}
					break;
				case CHAROID:
				case VARCHAROID:
				case TEXTOID:
				case JSONOID:
				case XMLOID:
				case UUIDOID:
				case BPCHAROID: // Bit string
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_string;
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_STRING(d, (char*)value);
					}
					break;
				case TIMESTAMPOID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_datetime;
						*(int64_t*)value = ntohll(*((int64_t*)value));
						*(int64_t*)value = *(int64_t*)value + (POSTGRES_EPOCH_JDATE - DU_EPOCH_JDATE) * USECS_PER_DAY;
						//DEBUGPOINT("TS = [%lld]\n", *(int64_t*)value);
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case DATEOID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_date;
						*(int32_t*)value = ntohl(*((int32_t*)value));
						*(int32_t*)value = *(int32_t*)value + (POSTGRES_EPOCH_JDATE - DU_EPOCH_JDATE);
						int64_t *ptr = (int64_t*)PQresultAlloc(statement->result, sizeof(int64_t));
						*ptr = *(int32_t*)value * USECS_PER_DAY;
						//DEBUGPOINT("D = [%lld]\n", *ptr);
						result_columns[i].val = (void*)ptr;
						result_columns[i].size = sizeof(int64_t);
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case TIMEOID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_time;
						*(int64_t*)value = ntohll(*((int64_t*)value));
						//DEBUGPOINT("T = [%lld]\n", *(int64_t*)value);
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case INTERVALOID:
					{
						interval_p_type interval;
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_duration;
						interval = pqt_get_interval(statement->result, value);
						//DEBUGPOINT("INTERVAL = [%d] [%d] [%lld]\n", interval->mon, interval->day, interval->usec);
						result_columns[i].val = (void*)interval;
						result_columns[i].size = sizeof(interval_s_type);
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				//case BYTEAARRAYOID:
				case BYTEAOID:
					{
						result_columns[i].name = name;
						result_columns[i].type = ev_lua_binary;
						result_columns[i].val = (void*)value;
						result_columns[i].size = length;
						LUA_PUSH_ARRAY_NIL(d);
					}
					break;
				case TIMESTAMPTZOID:
				case TIMETZOID:
				default:
					luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
			}
		}
	}

	lua_pushinteger(L, num_columns);
	lua_pushlightuserdata(L, result_columns);

	return 3;    
}

static int next_iterator(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, lua_upvalueindex(1), EV_POSTGRES_STATEMENT);

	return raw_statement_fetch_impl(L, statement);
}

/*
 * table = statement:fetch(named_indexes)
 */
static int statement_fetch(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_POSTGRES_STATEMENT);

	return raw_statement_fetch_impl(L, statement);
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

