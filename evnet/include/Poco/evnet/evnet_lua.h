#ifndef EVNET_LUA_INCLUDED
#define EVNET_LUA_INCLUDED

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <map>
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVEventNotification.h"

struct gen_lua_user_data_t {
	char * meta_table_name;
	void * user_data;
	size_t	size;
	gen_lua_user_data_t() {
		meta_table_name=0;
		user_data=0;
		size=0;
	}
	~gen_lua_user_data_t() {
		if (meta_table_name) {
			//DEBUGPOINT("Here %p:%s\n", meta_table_name, meta_table_name);
			free(meta_table_name);
		}
		meta_table_name=0;
		if (user_data) {
			//DEBUGPOINT("Here %p\n", user_data);
			free(user_data);
		}
		user_data=0;
		size=0;
	}
} ;

typedef enum {
	EV_LUA_TINVALID=-1,
	EV_LUA_TNIL=0,
	EV_LUA_TBOOLEAN,
	EV_LUA_TINTEGER,
	EV_LUA_TNUMBER,
	EV_LUA_TSTRING,
	EV_LUA_TLIGHTUSERDATA,
	EV_LUA_TTABLE,
	EV_LUA_TFUNCTION,
	EV_LUA_TUSERDATA,
	EV_LUA_TTHREAD,
	EV_LUA_TNONE
} ev_lua_type_enum;

typedef gen_lua_user_data_t* gen_lua_user_data_ptr_t;

typedef union _evnet_gen_value_t evnet_gen_value_t;

typedef struct _evnet_lua_table_value_t evnet_lua_table_value_t;

typedef std::map<std::string,evnet_lua_table_value_t> evnet_lua_table_t;

union _evnet_gen_value_t {
	void* nilpointer_value;
	int bool_value;
	int int_value;
	lua_Number number_value;
	char* string_value;
	void* lightuserdata_value;
	evnet_lua_table_t* table_value;
	void* function_value;
	void* userdata_value_from_lua;
	struct gen_lua_user_data_t* userdata_value_to_lua;
	void* thread_value;
	void* none_value;
	
};

struct _evnet_lua_table_value_t {
	ev_lua_type_enum type;
	union _evnet_gen_value_t value;

	_evnet_lua_table_value_t() {
	}
	~_evnet_lua_table_value_t() {
		//DEBUGPOINT("Here\n");
	}
} ;


typedef struct _ev_lua_var_s_t ev_lua_var_s_t;
typedef struct _ev_lua_var_s_t* ev_lua_var_p_t;

typedef struct _generic_task_params_t generic_task_params_t;
typedef struct _generic_task_params_t* generic_task_params_ptr_t;


extern "C" {
Poco::evnet::EVLHTTPRequestHandler* get_req_handler_instance(lua_State* L);
generic_task_params_ptr_t pack_lua_stack_in_params(lua_State *L, bool use_upvalue = false);
void push_out_params_to_lua_stack(generic_task_params_ptr_t params, lua_State *L);
int set_lua_stack_out_param(generic_task_params_ptr_t params, ev_lua_type_enum type, void * p);
generic_task_params_ptr_t destroy_generic_task_out_params(generic_task_params_ptr_t params);
generic_task_params_ptr_t destroy_generic_task_in_params(generic_task_params_ptr_t params);
void* get_generic_task_ptr_param(generic_task_params_ptr_t p, unsigned int loc);
ev_lua_type_enum get_generic_task_param_type(generic_task_params_ptr_t p, unsigned int loc);
generic_task_params_ptr_t new_generic_task_params();
int get_num_generic_params(generic_task_params_ptr_t p);
int get_generic_task_int_param(generic_task_params_ptr_t p, unsigned int loc);
int get_generic_task_bool_param(generic_task_params_ptr_t p, unsigned int loc);
lua_Number get_generic_task_luan_param(generic_task_params_ptr_t p, unsigned int loc);
void add_nv_tuple(evnet_lua_table_t* map, const char* name, evnet_lua_table_value_t& value);
void add_iv_tuple(evnet_lua_table_t* map, int index, evnet_lua_table_value_t& value);
}

#endif
