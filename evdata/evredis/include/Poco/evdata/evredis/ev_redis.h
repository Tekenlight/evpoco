#ifndef EV_REDIS_H_INCLUDED
#define EV_REDIS_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <evpoco/hiredis/hiredis.h>
#include <evpoco/hiredis/async.h>
#include <evpoco/hiredis/adapters/libev.h>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <Poco/evdata/ev_sql_access.h>
#include <Poco/evnet/EVLHTTPRequestHandler.h>

#define EV_REDIS_CONNECTION	"REDIS_CONNECTION"

typedef void (*free_reply_funcptr_type)(void * p);

typedef struct _redis_connection {
	int orig_fd;
    redisAsyncContext *ac;
	std::string * s_host;
	std::string * s_dbname;
	int conn_in_error;
	free_reply_funcptr_type free_reply_obj;
} redis_connection_t;

class redis_queue_holder : public Poco::evnet::evl_pool::queue_holder {
	public:
	virtual Poco::evnet::evl_pool::queue_holder* clone()
	{
		return (Poco::evnet::evl_pool::queue_holder*)(new redis_queue_holder());
	}
	virtual ~redis_queue_holder() {
		redis_connection_t * conn = (redis_connection_t*)dequeue(_queue);
		while (conn) {
			redisAsyncFree(conn->ac);
			delete(conn->s_host);
			delete(conn->s_dbname);
			free(conn);
			conn = (redis_connection_t*)dequeue(_queue);
		}
		wf_destroy_ev_queue(_queue);
	}
};


#endif
