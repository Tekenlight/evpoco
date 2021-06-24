#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sqlite3.h>

#include <ev_queue.h>

#include <Poco/evdata/ev_sql_access.h>
#include <Poco/evnet/evnet_lua.h>

#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

using namespace Poco::evnet;

extern "C" {
int completion_common_routine(lua_State* L, int status, lua_KContext ctx);
void init_locks_if_not_done();
void sg_stmt_lock_wr_lock(int l);
void sg_stmt_lock_rd_lock(int l);
void sg_m_o_m_lock_wr_lock(int l);
void sg_m_o_m_lock_rd_lock(int l);
void sg_dbtmm_lock_wr_lock(int l);
void sg_dbtmm_lock_rd_lock(int l);
}

typedef std::map<std::string, evl_db_conn_pool::queue_holder *> db_type_map_type;
typedef std::map<std::string, std::string*> statements_map_type;
typedef std::map<std::string, void*> map_of_maps_type;

const char *ev_sql_strlower(char *in)
{
    char *s = in;

    while(*s) {
	*s= (*s <= 'Z' && *s >= 'A') ? (*s - 'A') + 'a' : *s;
	s++;
    }

    return in;
}

/*
 * replace '?' placeholders with {native_prefix}\d+ placeholders
 * to be compatible with native API
 */
char *ev_sql_replace_placeholders(lua_State *L, char native_prefix, const char *sql)
{
	size_t len = strlen(sql);
	int num_placeholders = 0;
	int extra_space = 0;
	size_t i;
	char *newsql;
	int newpos = 1;
	int ph_num = 1;
	int in_quote = 0;
	char format_str[4];

	format_str[0] = native_prefix;
	format_str[1] = '%';
	format_str[2] = 'u';
	format_str[3] = '\0';

	/*
	 * dumb count of all '?'
	 * this will match more placeholders than necessesary
	 * but it's safer to allocate more placeholders at the
	 * cost of a few bytes than risk a buffer overflow
	 */ 
	for (i = 1; i < len; i++) {
		if (sql[i] == '?') {
			num_placeholders++;
		}
	}

	/*
	 * this is MAX_PLACEHOLDER_SIZE-1 because the '?' is 
	 * replaced with '{native_prefix}'
	 */ 
	extra_space = num_placeholders * (MAX_PLACEHOLDER_SIZE-1); 

	/*
	 * allocate a new string for the converted SQL statement
	 */
	newsql = (char*)calloc(len+extra_space+1, sizeof(char));
	if(!newsql) {
		lua_pushliteral(L, "out of memory");
		/* lua_error does not return. */
		lua_error(L);
	}

	/* 
	 * copy first char. In valid SQL this cannot be a placeholder
	 */
	newsql[0] = sql[0];

	/* 
	 * only replace '?' not in a single quoted string
	 */
	for (i = 1; i < len; i++) {
		/*
		 * don't change the quote flag if the ''' is preceded 
		 * by a '\' to account for escaping
		 */
		if (sql[i] == '\'' && sql[i-1] != '\\') {
			in_quote = !in_quote;
		}

		if (sql[i] == '?' && !in_quote) {
			size_t n;

			if (ph_num > MAX_PLACEHOLDERS) {
				luaL_error(L,
					"Sorry, you are using more than %d placeholders. Use %c{num} format instead",
										MAX_PLACEHOLDERS, native_prefix);
			}

			n = snprintf(&newsql[newpos], MAX_PLACEHOLDER_SIZE, format_str, ph_num++);

			newpos += n;
		} else {
			newsql[newpos] = sql[i];
			newpos++;
		}
	}

	/* 
	 * terminate string on the last position 
	 */
	newsql[newpos] = '\0';

	/* fprintf(stderr, "[%s]\n", newsql); */
	return newsql;
}

void ev_sql_register(lua_State *L, const char *name,
		  const luaL_Reg *methods, const luaL_Reg *class_methods,
		  lua_CFunction gc, lua_CFunction tostring)
{
    /* Create a new metatable with the given name and then assign the methods
     * to it.  Set the __index, __gc and __tostring fields appropriately.
     */
    luaL_newmetatable(L, name);
    luaL_setfuncs(L, methods, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");

    lua_pushcfunction(L, tostring);
    lua_setfield(L, -2, "__tostring");

    /* Create a new table and register the class methods with it */
    lua_newtable(L);
    luaL_setfuncs(L, class_methods, 0);
}

int completion_common_routine(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	EVUpstreamEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() != 0) {
		char * msg = (char*)ctx;
		if (!msg) msg = (char*)"Error occured during invocation";
		luaL_error(L, msg);
		return 0;
	}
	generic_task_params_ptr_t oparams = (generic_task_params_ptr_t)(usN.getTaskReturnValue());
	usN.setTaskReturnValue(NULL);
	push_out_params_to_lua_stack(oparams, L);
	int n = get_num_generic_params(oparams);

	//DEBUGPOINT("Here\n");
	oparams = destroy_generic_task_out_params(oparams);
	//DEBUGPOINT("Here\n");
	return n;
}

std::string get_statement_key(lua_State* L)
{
	lua_Debug info;
	lua_getstack(L, 1, &info);
	lua_getinfo(L, "nSl", &info);

	std::string s = std::string(info.source) + ":" + std::to_string(info.currentline);

	return s;
}

std::string form_conn_key(const char * host, const char * dbname, const char * user)
{
	//std::string key = std::string(host) + std::string(dbname) + std::string(user);
	std::string key;
	key += host;
	key += (dbname);
	key += (user);
	return key;
}

static std::string form_db_name_key(const char * host, const char * dbname)
{
	std::string key;
	key += host;
	key += (dbname);
	return key;
}

static map_of_maps_type* get_map_of_maps(lua_State *L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	map_of_maps_type* m_o_m = reqHandler->getMapOfMaps();
	return m_o_m;
}

static db_type_map_type * get_db_type_map(map_of_maps_type* m_o_m)
{
	init_locks_if_not_done();

	db_type_map_type * dbtm = NULL;
	sg_m_o_m_lock_rd_lock(1);
	{
		auto it = m_o_m->find(DB_TYPES_MAP);
		if (m_o_m->end() == it) {

			sg_m_o_m_lock_rd_lock(0);
			sg_m_o_m_lock_wr_lock(1);
			{
				it = m_o_m->find(DB_TYPES_MAP);
				if (it == m_o_m->end()) {
					dbtm = (new db_type_map_type());
					(*m_o_m)[std::string(DB_TYPES_MAP)] = (void*)dbtm;
					//DEBUGPOINT("DBTM N = [%p]\n", dbtm);
				}
				else {
					dbtm = (db_type_map_type *) it->second;
					//DEBUGPOINT("DBTM O = [%p]\n", dbtm);
				}
			}
			sg_m_o_m_lock_wr_lock(0);
			sg_m_o_m_lock_rd_lock(1);

		}
		else {
			dbtm = (db_type_map_type *) it->second;
			//DEBUGPOINT("DBTM O = [%p]\n", dbtm);
		}
	}
	sg_m_o_m_lock_rd_lock(0);
	return dbtm;
}

void init_db_type(lua_State * L, const char * db_type, evl_db_conn_pool::queue_holder *qhf)
{
	init_locks_if_not_done();

	map_of_maps_type* m_o_m = get_map_of_maps(L);
	//DEBUGPOINT("\n");
	db_type_map_type * dbtm = get_db_type_map(m_o_m);

	sg_dbtmm_lock_rd_lock(1);
	{
		std::string name(db_type);
		auto it = dbtm->find(name);

		if (it == dbtm->end()) {

			sg_dbtmm_lock_rd_lock(0);
			sg_dbtmm_lock_wr_lock(1);

			it = dbtm->find(name);
			if (it == dbtm->end()) (*dbtm)[name] = qhf->clone();

			sg_dbtmm_lock_wr_lock(0);
			sg_dbtmm_lock_rd_lock(1);

		}
	}
	sg_dbtmm_lock_rd_lock(0);
	//DEBUGPOINT("Initialized DB [%s]\n", db_type);
}

static evl_db_conn_pool::queue_holder *
get_queue_holder(lua_State* L, const char * db_type, const char * host, const char * dbname)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	evl_db_conn_pool* pool = reqHandler->getDbConnPool();
	map_of_maps_type* m_o_m = get_map_of_maps(L);
	db_type_map_type * dbtm = get_db_type_map(m_o_m);

	std::string db_key = form_db_name_key(host, dbname);
	evl_db_conn_pool::queue_holder *qh = (evl_db_conn_pool::queue_holder*)pool->get_queue_holder(db_key);
	if (qh == NULL) {
		auto it = dbtm->find(db_type);
		if (dbtm->end() == it) {
			printf("Database type : %s not initialized\n", db_type);
			std::abort();
		}
		evl_db_conn_pool::queue_holder *qhf = (evl_db_conn_pool::queue_holder *)it->second;
		qh = pool->add_queue_holder(db_key, qhf);
	}

	return qh;
}

void * get_conn_from_pool(lua_State* L, const char * db_type, const char * host, const char * dbname)
{
	evl_db_conn_pool::queue_holder * qh = get_queue_holder(L, db_type, host, dbname);
	void * conn = dequeue(qh->_queue);

	//DEBUGPOINT("FOUND CONNECTION [%p] from pool\n", conn);
	return conn;
}

void add_conn_to_pool(lua_State* L, const char * db_type, const char * host, const char * dbname, void * conn)
{
	evl_db_conn_pool::queue_holder * qh = get_queue_holder(L, db_type, host, dbname);
	enqueue(qh->_queue, conn);

	//DEBUGPOINT("ADDED CONNECTION [%p] to pool\n", conn);
	return ;
}

static statements_map_type * get_statements_map(lua_State *L)
{
	map_of_maps_type* m_o_m = get_map_of_maps(L);
	statements_map_type * sm;
	{
		auto it = m_o_m->find(STATEMENTS_MAP);
		if (m_o_m->end() == it) {
			sm = (new statements_map_type());
			(*m_o_m)[std::string(STATEMENTS_MAP)] = (void*)sm;
		}
		else {
			sm = (statements_map_type *) it->second;
		}
	}
	return sm;
}

static const std::string * core_get_stmt_id_from_cache(lua_State *L, const char * statement)
{
	std::string s = statement;
	statements_map_type * sm = get_statements_map(L);

	const std::string * ret = NULL;
	auto it = sm->find(s);
	if (sm->end() == it) {
		ret = NULL;
	}
	else {
		ret = it->second;
	}

	return ret;
}

void add_stmt_id_to_chache(lua_State* L, const char * statement, std::string * p)
{
	statements_map_type * sm = get_statements_map(L);

	init_locks_if_not_done();

	std::string s = statement;
	sg_stmt_lock_wr_lock(1);
	if (core_get_stmt_id_from_cache(L, statement) == NULL) {
		(*sm)[s] = p;
	}
	sg_stmt_lock_wr_lock(0);
	return;
}

const std::string * get_stmt_id_from_cache(lua_State* L, const char * statement)
{
	init_locks_if_not_done();

	const std::string * ret = NULL;
	sg_stmt_lock_rd_lock(1);
	ret = core_get_stmt_id_from_cache(L, statement);
	sg_stmt_lock_rd_lock(0);
	return ret;
}

