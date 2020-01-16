#include <string.h>
#include <cassert>
#include "Poco/evnet/evnet_lua.h"


struct _ev_lua_var_s_t {
	ev_lua_type_enum type;
	long double value;
};

struct ptr_s {
	void* ptr;
	evnet_lua_table_t * table_map;
	struct gen_lua_user_data_t* gud;
};

struct _generic_task_params_t {
	int n;
	ev_lua_var_s_t one;
	ev_lua_var_s_t two;
	ev_lua_var_s_t three;
	ev_lua_var_s_t four;
	ev_lua_var_s_t five;
	ev_lua_var_s_t six;
	ev_lua_var_s_t seven;
	ev_lua_var_s_t eight;
	ev_lua_var_s_t nine;
	ev_lua_var_s_t ten;
	std::list<struct ptr_s> gc_list;
};

static int ev_to_lua_type_map[][2] = {
	{EV_LUA_TNIL, LUA_TNIL},
	{EV_LUA_TBOOLEAN, LUA_TBOOLEAN},
	{EV_LUA_TINTEGER, LUA_TNUMBER},
	{EV_LUA_TNUMBER, LUA_TNUMBER},
	{EV_LUA_TSTRING, LUA_TSTRING},
	{EV_LUA_TLIGHTUSERDATA, LUA_TLIGHTUSERDATA},
	{EV_LUA_TTABLE, LUA_TTABLE},
	{EV_LUA_TFUNCTION, LUA_TFUNCTION},
	{EV_LUA_TUSERDATA, LUA_TUSERDATA},
	{EV_LUA_TTHREAD, LUA_TTHREAD},
	{EV_LUA_TNONE, LUA_TNONE}
};

Poco::evnet::EVLHTTPRequestHandler* get_req_handler_instance(lua_State* L)
{
	lua_getglobal(L, "EVLHTTPRequestHandler*");
	Poco::evnet::EVLHTTPRequestHandler * req_h = (Poco::evnet::EVLHTTPRequestHandler*)lua_touserdata(L, -1);
	lua_pop(L, 1);
	if (req_h == NULL) {
		luaL_error(L, "Request handler instance not found in the platform");
	}
	return req_h;
}

static ev_lua_type_enum get_param_type(generic_task_params_ptr_t p, unsigned int loc)
{
	ev_lua_type_enum type = EV_LUA_TINVALID;
	poco_assert(loc <10);
	switch (loc) {
		case 0:
			type = (p->one.type);
			break;
		case 1:
			type = (p->two.type);
			break;
		case 2:
			type = (p->three.type);
			break;
		case 3:
			type = (p->four.type);
			break;
		case 4:
			type = (p->five.type);
			break;
		case 5:
			type = (p->six.type);
			break;
		case 6:
			type = (p->seven.type);
			break;
		case 7:
			type = (p->eight.type);
			break;
		case 8:
			type = (p->nine.type);
			break;
		case 9:
			type = (p->ten.type);
			break;
		default:
			poco_assert((1!=1));
			break;
	}
	return type;
}

static void set_param_type(generic_task_params_ptr_t p, unsigned int loc, ev_lua_type_enum type)
{
	poco_assert(loc <=10);
	switch (loc) {
		case 0:
			(p->one.type) = type;
			break;
		case 1:
			(p->two.type) = type;
			break;
		case 2:
			(p->three.type) = type;
			break;
		case 3:
			(p->four.type) = type;
			break;
		case 4:
			(p->five.type) = type;
			break;
		case 5:
			(p->six.type) = type;
			break;
		case 6:
			(p->seven.type) = type;
			break;
		case 7:
			(p->eight.type) = type;
			break;
		case 8:
			(p->nine.type) = type;
			break;
		case 9:
			(p->ten.type) = type;
			break;
		default:
			poco_assert((1!=1));
			break;
	}
	return ;
}

static void* get_param_location(generic_task_params_ptr_t p, unsigned int loc)
{
	void * address = NULL;
	poco_assert(loc <=10);
	switch (loc) {
		case 0:
			address = (void*)&(p->one.value);
			break;
		case 1:
			address = (void*)&(p->two.value);
			break;
		case 2:
			address = (void*)&(p->three.value);
			break;
		case 3:
			address = (void*)&(p->four.value);
			break;
		case 4:
			address = (void*)&(p->five.value);
			break;
		case 5:
			address = (void*)&(p->six.value);
			break;
		case 6:
			address = (void*)&(p->seven.value);
			break;
		case 7:
			address = (void*)&(p->eight.value);
			break;
		case 8:
			address = (void*)&(p->nine.value);
			break;
		case 9:
			address = (void*)&(p->ten.value);
			break;
		default:
			poco_assert((1!=1));
			break;
	}
	return address;
}

generic_task_params_ptr_t new_generic_task_params()
{
	generic_task_params_ptr_t p = (generic_task_params_ptr_t)malloc(sizeof(generic_task_params_t));
	memset(p, 0, sizeof(generic_task_params_t));

	return p;
}

int get_num_generic_params(generic_task_params_ptr_t p)
{
	return p->n;
}

void* get_generic_task_param(generic_task_params_ptr_t p, unsigned int loc)
{
	void * q = get_param_location(p, loc-1);
	return *(void**)q;
}

ev_lua_type_enum get_generic_task_param_type(generic_task_params_ptr_t p, unsigned int loc)
{
	return get_param_type(p, loc-1);
}

generic_task_params_ptr_t destroy_generic_task_out_params(generic_task_params_ptr_t params)
{
	int i = 0;
	for (i = 0; i < params->n; i++) {
		if (EV_LUA_TSTRING == get_param_type(params, i)) {
			free(*(void**)(get_param_location(params, i)));
		}
		else if (EV_LUA_TUSERDATA == get_param_type(params, i)) {
			gen_lua_user_data_t* gud = (gen_lua_user_data_t*)*(void**)get_param_location(params, i);
			delete gud;
		}
	}
	for (auto it = params->gc_list.begin(); it != params->gc_list.end(); it++) {
		if (it->ptr) free(it->ptr);
		else if (it->table_map) delete it->table_map;
		else if (it->gud) delete it->gud;
	}
	free(params);
	return NULL;
}

generic_task_params_ptr_t destroy_generic_task_in_params(generic_task_params_ptr_t params)
{
	for (int i = 0; i < params->n; i++) {
		if (EV_LUA_TSTRING == get_param_type(params, i)) {
			free(*(void**)(get_param_location(params, i)));
		}
	}
	for (auto it = params->gc_list.begin(); it != params->gc_list.end(); it++) {
		if (it->ptr) free(it->ptr);
		else if (it->table_map) delete it->table_map;
		else if (it->gud) delete it->gud;
	}
	free(params);
	return NULL;
}

static bool is_integer(std::string s)
{
	bool numeric = true;
	int len = strlen(s.c_str());
	for (int i = 0; i < len; i++) {
		if (!isdigit(s.c_str()[i])) {
			if (i>0) {
				numeric = false;
				break;
			} else {
				if (s.c_str()[i] != '+' && s.c_str()[i] != '-') {
					numeric = false;
					break;
				}
			}
		}
	}

	return numeric;
}

int set_lua_stack_out_param(generic_task_params_ptr_t params, ev_lua_type_enum type, void *p)
{
	int i = params->n;
	params->n++;
	//DEBUGPOINT("Here type = %d, index = %d, p = %p, *p = %p\n", type, index, p, *(void**)p);
	switch (type) {
		case EV_LUA_TNIL:
			{
			void* q = 0;
			memcpy(get_param_location(params, i), &q, sizeof(void*));
			set_param_type(params, i, EV_LUA_TNIL);
			break;
			}
		case EV_LUA_TBOOLEAN:
			{
			int b = *(int*)p;
			memcpy(get_param_location(params, i), &b, sizeof(int));
			set_param_type(params, i, EV_LUA_TBOOLEAN);
			break;
			}
		case EV_LUA_TINTEGER:
			{
			int b = *(int*)p;
			memcpy(get_param_location(params, i), &b, sizeof(int));
			set_param_type(params, i, EV_LUA_TINTEGER);
			break;
			}
		case EV_LUA_TNUMBER:
			{
			lua_Number b = *(lua_Number*)p;
			memcpy(get_param_location(params, i), &b, sizeof(lua_Number));
			set_param_type(params, i, EV_LUA_TNUMBER);
			break;
			}
		case EV_LUA_TSTRING:
			{
			size_t len = strlen((char*)((void*)p));
			char * q = (char*)malloc(len+1);
			memcpy(q, (void*)p, len);
			q[len] = '\0';
			memcpy(get_param_location(params, i), &q, sizeof(void*));
			memcpy((void*)((char*)get_param_location(params, i)+sizeof(void*)), &len, sizeof(size_t));
			set_param_type(params, i, EV_LUA_TSTRING);
			break;
			}
		case EV_LUA_TLIGHTUSERDATA:
			{
			void *b = p;
			memcpy(get_param_location(params, i), &b, sizeof(void*));
			set_param_type(params, i, EV_LUA_TLIGHTUSERDATA);
			break;
			}
		case EV_LUA_TTABLE:
			{
			evnet_lua_table_t * table = (evnet_lua_table_t*)p;
			memcpy(get_param_location(params, i), &table, sizeof(void*));
			set_param_type(params, i, EV_LUA_TTABLE);
			struct ptr_s p_s;
			p_s.ptr = 0;
			p_s.table_map = table;
			p_s.gud = 0;
			params->gc_list.push_back(p_s);
			break;
			}
		case EV_LUA_TFUNCTION:
			{
			void * b = p;
			memcpy(get_param_location(params, i), &b, sizeof(void*));
			set_param_type(params, i, EV_LUA_TFUNCTION);
			break;
			}
		case EV_LUA_TUSERDATA:
			{
			void* b = p;
			//gen_lua_user_data_t* gud= *(gen_lua_user_data_t**)p;
			//DEBUGPOINT("Here %p %s %zu\n", gud, gud->meta_table_name, gud->size);
			memcpy(get_param_location(params, i), &b, sizeof(void*));
			//gud = 0;
			//gud = (gen_lua_user_data_t*)*((void**)get_param_location(params,i));
			//DEBUGPOINT("Here %p %s %zu\n", gud, gud->meta_table_name, gud->size);
			set_param_type(params, i, EV_LUA_TUSERDATA);
			break;
			}
		case EV_LUA_TTHREAD:
			{
			/* Thread not supported */
			poco_assert((1!=1));
			std::abort();
			break;
			}
		case EV_LUA_TNONE:
			{
			void *b = 0;
			memcpy(get_param_location(params, i), &b, sizeof(void*));
			set_param_type(params, i, EV_LUA_TNONE);
			}
		default:
			poco_assert((1!=1));
			break;
	}
	return 1;
}

static void add_nv_tuple(evnet_lua_table_t* map, const char* name, evnet_lua_table_value_t& value)
{
	char map_name[256];
	sprintf(map_name, "001:%s", name);
	(*map)[map_name] = value;
}

static void add_iv_tuple(evnet_lua_table_t* map, int index, evnet_lua_table_value_t& value)
{
	char map_name[256];
	sprintf(map_name, "002:%d", index);
	(*map)[map_name] = value;
}

static evnet_lua_table_t * lua_to_evnet_table(generic_task_params_ptr_t params, lua_State * L, int position);

static void set_value_to_table_value(generic_task_params_ptr_t params, lua_State * L, evnet_lua_table_value_t * vp)
{
	switch (lua_type(L, -1)) {
		case LUA_TNIL:
			{
			vp->value.nilpointer_value = 0;
			vp->type = EV_LUA_TNIL;
			break;
			}
		case LUA_TBOOLEAN:
			{
			vp->value.bool_value = lua_toboolean(L, -1);
			vp->type = EV_LUA_TBOOLEAN;
			break;
			}
		case LUA_TNUMBER:
			{
			vp->value.number_value = lua_tonumber(L, -1);
			vp->type = EV_LUA_TNUMBER;
			break;
			}
		case LUA_TSTRING:
			{
			vp->value.string_value = strdup(lua_tostring(L, -1));
			struct ptr_s p_s;
			p_s.ptr = vp->value.string_value;
			p_s.table_map = 0;
			p_s.gud = 0;
			params->gc_list.push_back(p_s);
			vp->type = EV_LUA_TSTRING;
			break;
			}
		case LUA_TLIGHTUSERDATA:
			{
			vp->value.lightuserdata_value = lua_touserdata(L, -1);
			vp->type = EV_LUA_TLIGHTUSERDATA;
			break;
			}
		case LUA_TTABLE:
			{
			/*
			 * Top of the stack has the table which has to be 
			 * recursively traversed.
			 * */
			vp->value.table_value = lua_to_evnet_table(params, L, lua_gettop(L));
			struct ptr_s p_s;
			p_s.ptr = 0;
			p_s.table_map = vp->value.table_value;
			p_s.gud = 0;
			params->gc_list.push_back(p_s);
			vp->type = EV_LUA_TTABLE;
			break;
			}
		case LUA_TFUNCTION:
			{
			vp->value.function_value = (void*)lua_tocfunction(L, -1);
			vp->type = EV_LUA_TFUNCTION;
			break;
			}
		case LUA_TUSERDATA:
			{
			vp->value.userdata_value_from_lua = lua_touserdata(L, -1);
			vp->type = EV_LUA_TUSERDATA;
			break;
			}
		case LUA_TTHREAD:
			{
			vp->value.thread_value = lua_tothread(L, -1);
			vp->type = EV_LUA_TTHREAD;
			break;
			}
		case LUA_TNONE:
			{
			vp->value.none_value = 0;
			vp->type = EV_LUA_TNONE;
			break;
			}
		default:
			poco_assert((1!=1));
			break;
	}
	return;
}

/* This function does, depth first traversal of LUA_TTABLE */
static evnet_lua_table_t * lua_to_evnet_table(generic_task_params_ptr_t params, lua_State * L, int position)
{
	evnet_lua_table_t * table = new evnet_lua_table_t();
	evnet_lua_table_value_t value_s;

	lua_pushvalue(L, position);
	lua_pushnil(L);
	/* At this point -2 is TABLE and -1 is KEY */
	while (lua_next(L, -2) != 0) {
		/* At this original key is popped out and point -2 is NEW KEY and -1 is NEW VALUE */
		memset(&value_s, 0, sizeof(evnet_lua_table_value_t));
		set_value_to_table_value(params, L, &value_s);
		if (lua_isinteger(L, -2)) {
			add_iv_tuple(table, lua_tointeger(L, -2), value_s);
		}
		else {
			luaL_checkstring(L, -2);
			add_nv_tuple(table, lua_tostring(L, -2), value_s);
		}
		lua_pop(L, 1); // Popping the value here
		/* At this point -2 is TABLE and -1 is KEY */
	}
	/* At this point KEY is popped out */
	lua_pop(L, 1); // Popping the additional table that was created on top 

	return table;
}

generic_task_params_ptr_t pack_lua_stack_in_params(lua_State *L)
{
	int i = 0;
	generic_task_params_ptr_t params = new_generic_task_params();
	memset(params, 0, sizeof(generic_task_params_t));
	params->n = lua_gettop(L);
	for (i = 0; i < params->n; i++) {
		switch (lua_type(L, i+1)) {
			case LUA_TNIL:
				{
				void* p = 0;
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TNIL);
				break;
				}
			case LUA_TBOOLEAN:
				{
				int p = lua_toboolean(L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(int));
				set_param_type(params, i, EV_LUA_TBOOLEAN);
				break;
				}
			case LUA_TNUMBER:
				{
				lua_Number p = lua_tonumber(L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(lua_Number));
				set_param_type(params, i, EV_LUA_TNUMBER);
				break;
				}
			case LUA_TSTRING:
				{
				size_t len = 0;
				void * p = (void*)strdup(lua_tolstring(L, i+1, &len));
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				memcpy((void*)((char*)get_param_location(params, i)+sizeof(void*)), &len, sizeof(size_t));
				set_param_type(params, i, EV_LUA_TSTRING);
				break;
				}
			case LUA_TLIGHTUSERDATA:
				{
				void *p = (void*)lua_topointer(L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TLIGHTUSERDATA);
				break;
				}
			case LUA_TTABLE:
				{
				evnet_lua_table_t *p = lua_to_evnet_table(params, L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TTABLE);
				struct ptr_s p_s;
				p_s.ptr = 0;
				p_s.table_map = p;
				p_s.gud = 0;
				params->gc_list.push_back(p_s);
				break;
				}
			case LUA_TFUNCTION:
				{
				void *p = (void*)lua_topointer(L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TFUNCTION);
				/* We will not support function as input */
				poco_assert((1!=1));
				std::abort();
				break;
				}
			case LUA_TUSERDATA:
				{
				void *p = (void*)lua_topointer(L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TUSERDATA);
				break;
				}
			case LUA_TTHREAD:
				{
				void *p = (void*)lua_topointer(L, i+1);
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TTHREAD);
				/* We will not support thread as input */
				poco_assert((1!=1));
				std::abort();
				break;
				}
			case LUA_TNONE:
				{
				void * p = NULL;
				memcpy(get_param_location(params, i), &p, sizeof(void*));
				set_param_type(params, i, EV_LUA_TNONE);
				}
			default:
				poco_assert((1!=1));
				break;
		}
	}

	return params;
}

static void add_table_to_lua_stack(generic_task_params_ptr_t params, lua_State *L, evnet_lua_table_t *p);

/*
 * Assumption in this function is that the table to which value is being added is currently
 * at top of the stack.
 * */
static void push_item_to_lua_table(generic_task_params_ptr_t params, lua_State *L, const char * inp_name, evnet_lua_table_value_t* value_ptr)
{
	int int_type = (inp_name[2] == '2');
	const char* name = inp_name+4;
	int table_index = 0;

	if (int_type) {
		table_index = atoi(name);
	}

	switch(value_ptr->type) {
		case EV_LUA_TNIL:
			{
			lua_pushnil(L);
			break;
			}
		case EV_LUA_TBOOLEAN:
			{
			lua_pushboolean(L, value_ptr->value.bool_value);
			break;
			}
		case EV_LUA_TINTEGER:
			{
			lua_pushinteger(L, value_ptr->value.int_value);
			break;
			}
		case EV_LUA_TNUMBER:
			{
			lua_pushnumber(L, value_ptr->value.number_value);
			break;
			}
		case EV_LUA_TSTRING:
			{
			lua_pushstring(L, value_ptr->value.string_value);
			struct ptr_s p_s;
			p_s.ptr = value_ptr->value.string_value;
			p_s.table_map = 0;
			p_s.gud = 0;
			params->gc_list.push_back(p_s);
			break;
			}
		case EV_LUA_TLIGHTUSERDATA:
			{
			lua_pushlightuserdata(L, value_ptr->value.lightuserdata_value);
			break;
			}
		case EV_LUA_TTABLE:
			{
			lua_newtable(L);
			add_table_to_lua_stack(params, L, value_ptr->value.table_value);
			struct ptr_s p_s;
			p_s.ptr = 0;
			p_s.table_map = value_ptr->value.table_value;
			p_s.gud = 0;
			params->gc_list.push_back(p_s);
			break;
			}
		case EV_LUA_TFUNCTION:
			{
			//std::abort(" TBD: Still to decide, how to handle closures");
			std::abort();
			break;
			}
		case EV_LUA_TUSERDATA:
			{
			struct gen_lua_user_data_t* p = value_ptr->value.userdata_value_to_lua;
			poco_assert(p!=NULL);
			poco_assert(p->user_data!=NULL);
			poco_assert(p->meta_table_name!=NULL);
			poco_assert(p->size!=0);
			//DEBUGPOINT("Here %p %s %zu\n", p, p->meta_table_name, p->size);
			void * ptr = lua_newuserdata(L, p->size);
			memcpy(ptr, p->user_data, p->size);
			luaL_setmetatable(L, p->meta_table_name);
			struct ptr_s p_s;
			p_s.ptr = 0;
			p_s.table_map = 0;
			p_s.gud = p;
			params->gc_list.push_back(p_s);
			break;
			}
		case EV_LUA_TTHREAD:
			{
			//std::abort(" TBD: Still to decide, how to handle THREAD");
			std::abort();
			break;
			}
		case EV_LUA_TNONE:
			{
			//std::abort(" TBD: Still to decide, how to handle NONE");
			std::abort();
			}
		default:
			poco_assert((1!=1));
			break;
	}
	if (int_type) lua_seti(L, -2, table_index);
	else lua_setfield(L, -2, name);

	return ;
}

/*
 * Assumption in this function is that the table to which value is being added is currently
 * at top of the stack.
 * */
static void add_table_to_lua_stack(generic_task_params_ptr_t params, lua_State *L, evnet_lua_table_t *p)
{
	for (auto it = p->begin(); it != p->end(); it++) {
		push_item_to_lua_table(params, L, it->first.c_str(), &it->second);
	}
	return;
}

void push_out_params_to_lua_stack(generic_task_params_ptr_t params, lua_State *L)
{
	int i = 0;
	for (i = 0; i < params->n; i++) {
		switch (get_param_type(params, i)) {
			case EV_LUA_TNIL:
				{
				lua_pushnil(L);    
				break;
				}
			case EV_LUA_TBOOLEAN:
				{
				int p = (int)(long)*(void**)get_param_location(params, i);
				lua_pushboolean(L, p);
				break;
				}
			case EV_LUA_TINTEGER:
				{
				int p = (int)(long)*(void**)get_param_location(params, i);
				lua_pushinteger(L, p);
				break;
				}
			case EV_LUA_TNUMBER:
				{
				lua_Number p;
				 /*Number can be 128 bit or 64 bit, hence memcpy */
				memcpy(&p, get_param_location(params, i), sizeof(lua_Number));
				lua_pushnumber(L, p);
				break;
				}
			case EV_LUA_TSTRING:
				{
				char * p = (char*)*(void**)get_param_location(params, i);
				lua_pushstring(L, p);
				break;
				}
			case EV_LUA_TLIGHTUSERDATA:
				{
				void * p = *(void**)get_param_location(params, i);
				lua_pushlightuserdata(L, p);
				break;
				}
			case EV_LUA_TTABLE:
				{
				evnet_lua_table_t *p = *(evnet_lua_table_t**)(void**)get_param_location(params, i);
				lua_newtable(L);
				add_table_to_lua_stack(params, L, p);
				break;
				}
			case EV_LUA_TFUNCTION:
				{
				//std::abort(" TBD: Still to decide, how to handle closures");
				std::abort();
				break;
				}
			case EV_LUA_TUSERDATA:
				{
				gen_lua_user_data_ptr_t p = (gen_lua_user_data_ptr_t)*(void**)get_param_location(params, i);
				poco_assert(p!=NULL);
				poco_assert(p->user_data!=NULL);
				poco_assert(p->meta_table_name!=NULL);
				poco_assert(p->size!=0);
				//DEBUGPOINT("Here %p %s %zu\n", p, p->meta_table_name, p->size);
				void * ptr = lua_newuserdata(L, p->size);
				memcpy(ptr, p->user_data, p->size);
				luaL_setmetatable(L, p->meta_table_name);
				break;
				}
			case EV_LUA_TTHREAD:
				{
				//std::abort(" TBD: Still to decide, how to handle THREAD");
				std::abort();
				break;
				}
			case EV_LUA_TNONE:
				{
				//std::abort(" TBD: Still to decide, how to handle NONE");
				std::abort();
				}
			default:
				poco_assert((1!=1));
				break;
		}
	}

	return ;
}


