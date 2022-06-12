#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sqlite3.h>

#include <ev_queue.h>

#include <Poco/evnet/evnet_lua.h>

#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

#define TYPES_MAP "TYPES"
#define STATEMENTS_MAP "STATEMENTS"

using namespace Poco::evnet;

extern "C" {
int completion_common_routine(lua_State* L, int status, lua_KContext ctx);
void init_locks_if_not_done();
void sg_stmt_lock_wr_lock(int l);
void sg_stmt_lock_rd_lock(int l);
void sg_m_o_m_lock_wr_lock(int l);
void sg_m_o_m_lock_rd_lock(int l);
void sg_tmm_lock_wr_lock(int l);
void sg_tmm_lock_rd_lock(int l);
}

typedef std::map<std::string, evl_pool::queue_holder *> type_map_type;
typedef std::map<std::string, const char*> statements_map_type;
typedef std::map<std::string, void*> map_of_maps_type;

static map_of_maps_type * sg_m_o_m = NULL;;

static std::string form_name_key(const char * host, const char * name)
{
	std::string key;
	key += host;
	key += (name);
	return key;
}

#define init_m_o_m() {\
	sg_m_o_m_lock_rd_lock(1); \
	if (sg_m_o_m == NULL) { \
		sg_m_o_m_lock_rd_lock(0); \
		sg_m_o_m_lock_wr_lock(1); \
		if (sg_m_o_m == NULL) { \
			sg_m_o_m = EVLHTTPRequestHandler::getMapOfMaps(); \
		} \
		sg_m_o_m_lock_wr_lock(0); \
		sg_m_o_m_lock_rd_lock(1); \
	} \
	sg_m_o_m_lock_rd_lock(0); \
}
#define get_map_of_maps() sg_m_o_m;

static type_map_type * add_and_get_type_map(map_of_maps_type* m_o_m)
{
	init_locks_if_not_done();

	type_map_type * tm = NULL;
	sg_m_o_m_lock_rd_lock(1);
	{
		auto it = m_o_m->find(TYPES_MAP);
		if (m_o_m->end() == it) {

			sg_m_o_m_lock_rd_lock(0);
			sg_m_o_m_lock_wr_lock(1);
			{
				auto it = m_o_m->find(TYPES_MAP);
				if (it == m_o_m->end()) {
					tm = (new type_map_type());
					(*m_o_m)[std::string(TYPES_MAP)] = (void*)tm;
					//DEBUGPOINT("TM N = [%p]\n", tm);
				}
				else {
					tm = (type_map_type *) it->second;
					//DEBUGPOINT("TM O = [%p]\n", tm);
				}
			}
			sg_m_o_m_lock_wr_lock(0);
			sg_m_o_m_lock_rd_lock(1);

		}
		else {
			tm = (type_map_type *) it->second;
			//DEBUGPOINT("TM O = [%p]\n", tm);
		}
	}
	sg_m_o_m_lock_rd_lock(0);
	return tm;
}

static type_map_type * get_type_map(map_of_maps_type* m_o_m)
{
	init_locks_if_not_done();

	type_map_type * tm = NULL;
	sg_m_o_m_lock_rd_lock(1);
	{
		auto it = m_o_m->find(TYPES_MAP);
		if (m_o_m->end() == it) {
			//DEBUGPOINT("THIS IS AN IMPOSSIBLE CONDITION\n");
			std::abort();
		}
		else {
			tm = (type_map_type *) it->second;
			//DEBUGPOINT("TM O = [%p]\n", tm);
		}
	}
	sg_m_o_m_lock_rd_lock(0);
	return tm;
}

void init_pool_type(const char * type, evl_pool::queue_holder *qhf)
{
	init_locks_if_not_done();
	init_m_o_m();

	map_of_maps_type* m_o_m = get_map_of_maps();
	type_map_type* tm = add_and_get_type_map(m_o_m);

	sg_tmm_lock_rd_lock(1);
	{
		std::string name(type);
		auto it = tm->find(name);

		//DEBUGPOINT("Here\n");
		if (it == tm->end()) {
			//DEBUGPOINT("Here\n");

			sg_tmm_lock_rd_lock(0);
			sg_tmm_lock_wr_lock(1);

			it = tm->find(name);
			if (it == tm->end()) (*tm)[name] = qhf->clone();

			sg_tmm_lock_wr_lock(0);
			sg_tmm_lock_rd_lock(1);

		}
		//DEBUGPOINT("Here\n");
	}
	sg_tmm_lock_rd_lock(0);
	//DEBUGPOINT("Initialized type [%s]\n", type);
}

static evl_pool::queue_holder *
get_queue_holder(const char * type, const char * host, const char * name)
{
	evl_pool* pool = EVLHTTPRequestHandler::getPool();
	map_of_maps_type* m_o_m = get_map_of_maps();
	type_map_type* tm = get_type_map(m_o_m);

	std::string key = form_name_key(host, name);
	//DEBUGPOINT("KEY = [%s]\n", key.c_str());
	evl_pool::queue_holder *qh = pool->get_queue_holder(key);
	if (qh == NULL) {
		auto it = tm->find(type);
		if (tm->end() == it) {
			DEBUGPOINT("Here type[%s]\n", type);
			printf("POOL type : [%s] not initialized\n", type);
			std::abort();
		}
		evl_pool::queue_holder *qhf = (evl_pool::queue_holder *)it->second;
		qh = pool->add_queue_holder(key, qhf);
	}
	//DEBUGPOINT("qh = [%p]\n", qh);

	return qh;
}

void * get_conn_from_pool(const char * type, const char * host, const char * name)
{
	evl_pool::queue_holder * qh = get_queue_holder(type, host, name);
	void * conn = dequeue(qh->_queue);

	//DEBUGPOINT("FOUND CONNECTION [%p] from pool\n", conn);
	return conn;
}

void add_conn_to_pool(const char * type, const char * host, const char * name, void * conn)
{
	evl_pool::queue_holder * qh = get_queue_holder(type, host, name);
	enqueue(qh->_queue, conn);

	//DEBUGPOINT("ADDED CONNECTION [%p] to pool\n", conn);
	return ;
}

void add_conn_to_pool(const char * type, const char * name, void * conn)
{
	return add_conn_to_pool(type, "", name, conn);

	return ;
}

void * get_conn_from_pool(const char * type, const char * name)
{
	return get_conn_from_pool(type, "", name);
}

static statements_map_type * get_statements_map()
{
	map_of_maps_type* m_o_m = get_map_of_maps();
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

static const char* core_get_stmt_id_from_cache(const char * statement)
{
	std::string s = statement;
	statements_map_type * sm = get_statements_map();

	const char* ret = NULL;
	auto it = sm->find(s);
	if (sm->end() == it) {
		ret = NULL;
	}
	else {
		ret = it->second;
	}

	return ret;
}

void add_stmt_id_to_chache(const char * statement, const char* p)
{
	statements_map_type * sm = get_statements_map();

	init_locks_if_not_done();

	std::string s = statement;
	sg_stmt_lock_wr_lock(1);
	if (core_get_stmt_id_from_cache(statement) == NULL) {
		(*sm)[s] = p;
	}
	sg_stmt_lock_wr_lock(0);
	return;
}

const char* get_stmt_id_from_cache(const char * statement)
{
	init_locks_if_not_done();

	const char* ret = NULL;
	sg_stmt_lock_rd_lock(1);
	ret = core_get_stmt_id_from_cache(statement);
	sg_stmt_lock_rd_lock(0);
	return ret;
}

