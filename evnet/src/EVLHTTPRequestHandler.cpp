//
// EVLHTTPRequestHandler.cpp
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVLHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#include <ev_rwlock.h>
#include <chunked_memory_stream.h>

#include "Poco/Util/Application.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/CountingStream.h"
#include "Poco/NullStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/DateTimeParser.h"
#include "Poco/DateTime.h"
#include "Poco/URI.h"

#include "Poco/evnet/evnet_lua.h"


namespace Poco {
namespace evnet {

const static char *_html_form_type_name = "htmlform";
const static char *_http_req_type_name = "httpreq";
const static char *_http_resp_type_name = "httpresp";
const static char *_platform_name = "platform";

namespace evpoco {
	static int get_http_request(lua_State* L);
	static int get_http_response(lua_State* L);
	static int resolve_host_address_complete(lua_State* L, int status, lua_KContext ctx);
	static int resolve_host_address_initiate(lua_State* L);
	static int make_http_connection_complete(lua_State* L, int status, lua_KContext ctx);
	static int make_http_connection_initiate(lua_State* L);
	static int close_http_connection(lua_State* L);
	static int new_request(lua_State* L);
	static int send_request_header(lua_State* L);
	static int send_request_body(lua_State* L);
	static int receive_http_response_initiate(lua_State* L);
	static int receive_http_response_complete(lua_State* L, int status, lua_KContext ctx);
	namespace httpmessage {
		static int set_version(lua_State* L);
		static int get_version(lua_State* L);
		static int set_chunked_trfencoding(lua_State* L);
		static int get_chunked_trfencoding(lua_State* L);
		static int set_content_length(lua_State* L);
		static int get_content_length(lua_State* L);
		static int set_trf_encoding(lua_State* L);
		static int get_trf_encoding(lua_State* L);
		static int set_content_type(lua_State* L);
		static int get_content_type(lua_State* L);
		static int set_keep_alive(lua_State* L);
		static int get_keep_alive(lua_State* L);
		static int set_hdr_field(lua_State* L);
		static int get_hdr_field(lua_State* L);
		static int get_hdr_fields(lua_State* L);
		namespace httpreq {
			static int parse_form(lua_State* L);
			static int get_part_names(lua_State* L);
			static int get_part(lua_State* L);
			static int get_query_parameters(lua_State* L);
			static int set_uri(lua_State* L);
			static int get_uri(lua_State* L);
			static int set_method(lua_State* L);
			static int get_method(lua_State* L);
			static int set_host(lua_State* L);
			static int get_host(lua_State* L);
			static int set_expect_continue(lua_State* L);
			static int get_expect_continue(lua_State* L);
			static int write(lua_State* L);
			static int read(lua_State* L);
			static int get_cookies(lua_State* L);
			namespace htmlform {
				static int get_form_field(lua_State* L);
				struct form_iterator {
					Poco::Net::NameValueCollection::ConstIterator it;
					Poco::Net::NameValueCollection::ConstIterator last;
				};
				static int begin_iteration(lua_State* L);
				static int next_iteration(lua_State* L);
				static int empty(lua_State* L);
			}
		}
		namespace httpresp {
			static int set_status(lua_State* L);
			static int set_date(lua_State* L);
			static int send(lua_State* L);
			static int write(lua_State* L);
			static int read(lua_State* L);
			static int get_cookies(lua_State* L);
		}
	}
}

static const luaL_Reg dummy[] = {
	{ NULL, NULL }
};

static const luaL_Reg form_lib[] = {
	{ "get_form_field", &evpoco::httpmessage::httpreq::htmlform::get_form_field },
	{ "begin_iteration", &evpoco::httpmessage::httpreq::htmlform::begin_iteration},
	{ "next_iteration", &evpoco::httpmessage::httpreq::htmlform::next_iteration},
	{ "empty", &evpoco::httpmessage::httpreq::htmlform::empty},
	{ NULL, NULL }
};

static const luaL_Reg evpoco_httpreq_lib[] = {
	{ "set_version", &evpoco::httpmessage::set_version },
	{ "get_version", &evpoco::httpmessage::get_version },
	{ "set_chunked_trfencoding", &evpoco::httpmessage::set_chunked_trfencoding },
	{ "get_chunked_trfencoding", &evpoco::httpmessage::get_chunked_trfencoding },
	{ "set_content_length", &evpoco::httpmessage::set_content_length },
	{ "get_content_length", &evpoco::httpmessage::get_content_length },
	{ "set_trf_encoding", &evpoco::httpmessage::set_trf_encoding },
	{ "get_trf_encoding", &evpoco::httpmessage::get_trf_encoding },
	{ "set_content_type", &evpoco::httpmessage::set_content_type },
	{ "get_content_type", &evpoco::httpmessage::get_content_type },
	{ "set_keep_alive", &evpoco::httpmessage::set_keep_alive },
	{ "get_keep_alive", &evpoco::httpmessage::get_keep_alive },
	{ "get_hdr_fields", &evpoco::httpmessage::get_hdr_fields },
	{ "set_hdr_field", &evpoco::httpmessage::set_hdr_field },
	{ "get_hdr_field", &evpoco::httpmessage::get_hdr_field },
	{ "set_method", &evpoco::httpmessage::httpreq::set_method },
	{ "get_method", &evpoco::httpmessage::httpreq::get_method },
	{ "set_host", &evpoco::httpmessage::httpreq::set_host },
	{ "get_host", &evpoco::httpmessage::httpreq::get_host },
	{ "set_expect_continue", &evpoco::httpmessage::httpreq::set_expect_continue },
	{ "get_expect_continue", &evpoco::httpmessage::httpreq::get_expect_continue },
	{ "set_uri", &evpoco::httpmessage::httpreq::set_uri },
	{ "get_uri", &evpoco::httpmessage::httpreq::get_uri },
	{ "get_query_parameters", &evpoco::httpmessage::httpreq::get_query_parameters },
	{ "parse_req_form", &evpoco::httpmessage::httpreq::parse_form },
	{ "get_part_names", &evpoco::httpmessage::httpreq::get_part_names },
	{ "get_part", &evpoco::httpmessage::httpreq::get_part},
	{ "write", &evpoco::httpmessage::httpreq::write},
	{ "read", &evpoco::httpmessage::httpreq::read},
	{ "get_cookies", &evpoco::httpmessage::httpreq::get_cookies},
	{ NULL, NULL }
};

static const luaL_Reg evpoco_httpresp_lib[] = {
	{ "set_version", &evpoco::httpmessage::set_version },
	{ "get_version", &evpoco::httpmessage::get_version },
	{ "set_chunked_trfencoding", &evpoco::httpmessage::set_chunked_trfencoding },
	{ "get_chunked_trfencoding", &evpoco::httpmessage::get_chunked_trfencoding },
	{ "set_content_length", &evpoco::httpmessage::set_content_length },
	{ "get_content_length", &evpoco::httpmessage::get_content_length },
	{ "set_trf_encoding", &evpoco::httpmessage::set_trf_encoding },
	{ "get_trf_encoding", &evpoco::httpmessage::get_trf_encoding },
	{ "set_content_type", &evpoco::httpmessage::set_content_type },
	{ "get_content_type", &evpoco::httpmessage::get_content_type },
	{ "set_keep_alive", &evpoco::httpmessage::set_keep_alive },
	{ "get_keep_alive", &evpoco::httpmessage::get_keep_alive },
	{ "set_hdr_field", &evpoco::httpmessage::set_hdr_field },
	{ "get_hdr_field", &evpoco::httpmessage::get_hdr_field },
	{ "get_hdr_fields", &evpoco::httpmessage::get_hdr_fields },
	{ "set_status", &evpoco::httpmessage::httpresp::set_status },
	{ "set_date", &evpoco::httpmessage::httpresp::set_date },
	{ "send", &evpoco::httpmessage::httpresp::send },
	{ "write", &evpoco::httpmessage::httpresp::write },
	{ "read", &evpoco::httpmessage::httpresp::read },
	{ "get_cookies", &evpoco::httpmessage::httpresp::get_cookies },
	{ NULL, NULL }
};

static const luaL_Reg evpoco_lib[] = {
	{ "get_http_request", &evpoco::get_http_request },
	{ "get_http_request", &evpoco::get_http_request },
	{ "get_http_response", &evpoco::get_http_response },
	{ "resolve_host_address", &evpoco::resolve_host_address_initiate },
	{ "make_http_connection", &evpoco::make_http_connection_initiate },
	{ "close_http_connection", &evpoco::close_http_connection},
	{ "new_request", &evpoco::new_request},
	{ "send_request_header", &evpoco::send_request_header },
	{ "send_request_body", &evpoco::send_request_body },
	{ "receive_http_response", &evpoco::receive_http_response_initiate },
	{ NULL, NULL }
};

typedef struct LoadS {
	chunked_memory_stream *_cms;
	void *_buffer_node;
	size_t _size;
} LoadS;

class LUAFileCache {
public:
	std::map<std::string, chunked_memory_stream*> cached_files;
	std::map<std::string, std::string> cached_filepaths;
	ev_rwlock_type lock;
	ev_rwlock_type cached_files_lock;
	ev_rwlock_type cached_filepaths_lock;
	LUAFileCache() {
		//DEBUGPOINT("Here\n");
		cached_files_lock = ev_rwlock_init();
		cached_filepaths_lock = ev_rwlock_init();
	}
	~LUAFileCache() {
		ev_rwlock_destroy(cached_files_lock);
		ev_rwlock_destroy(cached_filepaths_lock);
	}
};

static LUAFileCache sg_file_cache;

static const char *getCB (lua_State *L, void *ud, size_t *size)
{
	LoadS *ls = (LoadS *)ud;
	(void)L;  /* not used */
	if (ls->_cms == NULL) return NULL;
	ls->_buffer_node = ls->_cms->get_next(ls->_buffer_node);
	*size = ls->_cms->get_buffer_len(ls->_buffer_node);

	return (char*)(ls->_cms->get_buffer(ls->_buffer_node));
}

static int cacheCB(lua_State *L, void * p, size_t sz, void* ud)
{
	LoadS *ls = (LoadS *)ud;
	(void)L;  /* not used */
	if (ls->_cms == NULL) LUA_ERRRUN;
	void * buffer = malloc(sz+1);
	memset(buffer, 0, (sz+1));
	memcpy(buffer, p, sz);
	ls->_cms->push(buffer, sz);

	return LUA_OK;
}

static int luaL_checkfilecacheexists(lua_State *L, const char *name)
{
	ev_rwlock_rdlock(sg_file_cache.cached_files_lock);
	chunked_memory_stream *cms = sg_file_cache.cached_files[name];
	ev_rwlock_rdunlock(sg_file_cache.cached_files_lock);
	if (!cms) {
		//DEBUGPOINT("CH_FILE:Here no %s\n", name);
		return 0;
	}
	//DEBUGPOINT("CH_FILE:Here yes %s\n", name);
	return 1;
}

static int luaL_cacheloadedfile(lua_State *L, const char *name)
{
	if (luaL_checkfilecacheexists(L, name)) {
		//DEBUGPOINT("CHACHE_REQ:Already cached %s\n", name);
		return LUA_OK;
	}
	chunked_memory_stream * cms = new chunked_memory_stream();
	LoadS ls ;
	ls._cms = cms;
	ls._buffer_node = NULL;
	ls._size=0;
	lua_dump(L, (lua_Writer)cacheCB, (void*)&ls, 0);

	ev_rwlock_wrlock(sg_file_cache.cached_files_lock);
	if (!sg_file_cache.cached_files[name]) {
		//DEBUGPOINT("CHACHE_REQ:Here caching %s\n", name);
		sg_file_cache.cached_files[name] = cms;
	}
	else {
		//DEBUGPOINT("CHACHE_REQ:Here deleting cms due to concurrency !!!\n");
		delete cms;
	}
	ev_rwlock_wrunlock(sg_file_cache.cached_files_lock);
	//DEBUGPOINT("CACHE_REQ:Here now cached %s\n", name);
	return LUA_OK;
}

static const char * luaL_getcachedpath(lua_State *L, const char *name)
{
	const char *filename = NULL;
	try {
		ev_rwlock_rdlock(sg_file_cache.cached_filepaths_lock);
		std::string &filepath = sg_file_cache.cached_filepaths.at(name);
		ev_rwlock_rdunlock(sg_file_cache.cached_filepaths_lock);
		lua_pushstring(L, filepath.c_str());
		filename = lua_tostring(L, -1);
	} catch (std::exception & e) {
		ev_rwlock_rdunlock(sg_file_cache.cached_filepaths_lock);
		lua_pushfstring(L, "\n\tno file '%s'", name);
	}
	return filename;
}

static int luaL_addfilepathtocache(lua_State *L, const char *name, const char * path)
{
	ev_rwlock_wrlock(sg_file_cache.cached_filepaths_lock);
	sg_file_cache.cached_filepaths[name] = std::string(path);
	ev_rwlock_wrunlock(sg_file_cache.cached_filepaths_lock);

	return LUA_OK;
}

static int luaL_loadcachedbufferx(lua_State *L, const char *name, const char *mode)
{
	LoadS ls;
	ev_rwlock_rdlock(sg_file_cache.cached_files_lock);
	ls._cms = sg_file_cache.cached_files[name];
	ev_rwlock_rdunlock(sg_file_cache.cached_files_lock);
	if (!ls._cms) return LUA_ERRRUN;
	ls._buffer_node = NULL;
	ls._size = 0;
	//DEBUGPOINT("LOAD_REQ:Here for %s\n", name);
	return lua_load(L, getCB, &ls, name, mode);
}

static void v_hello_world(void* v)
{
	DEBUGPOINT("Here\n");
	//free(v);
	return;
}

static int obj1__gc(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);


	return 0;
}

static int obj__gc(lua_State *L)
{
	return 0;
}

namespace evpoco {

	static int evpoco_sleep(lua_State* L)
	{
		//DEBUGPOINT("Here\n");
		useconds_t duration = 0;
		if ((0 != lua_gettop(L)) && (lua_isinteger(L, 1))) {
			lua_numbertointeger(lua_tonumber(L, 1), &duration);
		}
		//DEBUGPOINT("Here %d\n", duration);

		usleep(duration);

		/*
		Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		poco_assert(reqHandler != NULL);
		Poco::evnet::EVServer * server = reqHandler->getServerPtr();
		server->submitRequestForTaskExecutionNR(v_hello_world, 0);
		*/

		return 0;
	}

	static int get_http_request(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		Net::HTTPServerRequest& request = reqHandler->getRequest();

		void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerRequest*));
		*(Net::HTTPServerRequest**)ptr = &request;
		luaL_setmetatable(L, _http_req_type_name);

		return 1;
	}

	static int get_http_response(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		Net::HTTPServerResponse& response = reqHandler->getResponse();

		void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerResponse*));
		*(Net::HTTPServerResponse**)ptr = &response;
		luaL_setmetatable(L, _http_resp_type_name);

		return 1;
	}

	static int resolve_host_address_complete(lua_State* L, int status, lua_KContext ctx)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		struct addrinfo** addr_info_ptr_ptr = (struct addrinfo**)ctx;

		//DEBUGPOINT("HERE\n");

		Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
		if (usN.getRet() != 0) {
			luaL_error(L, "resolve_host_address: address resolution could not happen: %s", strerror(usN.getErrNo()));
			if (usN.getAddrInfo()) {
				freeaddrinfo(usN.getAddrInfo());
			}
			free(addr_info_ptr_ptr);
			return 0;
		}

		struct addrinfo *p = *addr_info_ptr_ptr;
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
		int i = 0;

		lua_newtable (L);
		for (; p; p = p->ai_next) {
			i++;
			getnameinfo(p->ai_addr, p->ai_addrlen, hbuf, sizeof (hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST|NI_NUMERICSERV);
			lua_newtable (L);
			lua_pushstring(L, "hostaddress");
			lua_pushstring(L, hbuf);
			lua_settable(L, -3);
			lua_pushstring(L, "portnum");
			lua_pushstring(L, sbuf);
			lua_settable(L, -3);
			if (p->ai_addr->sa_family == AF_INET) {
				lua_pushstring(L, "addrfamily");
				lua_pushstring(L, "4");
				lua_settable(L, -3);
			}
			else {
				lua_pushstring(L, "addrfamily");
				lua_pushstring(L, "6");
				lua_settable(L, -3);
			}
			lua_seti(L, -2, i);
		}

		freeaddrinfo(*(addr_info_ptr_ptr));
		free(addr_info_ptr_ptr);

		return 1;
	}

	static int resolve_host_address_initiate(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		struct addrinfo** addr_info_ptr_ptr = NULL;
		if (lua_gettop(L) != 2) {
			luaL_error(L, "resolve_host_address: invalid number of arguments, expected 2, actual %d ", lua_gettop(L));
			return 0;
		}
		else if (lua_isnil(L, -2) || !lua_isstring(L, -2)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
			luaL_error(L, "resolve_host_address: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
			return 0;
		}
		else if (!lua_isnil(L, -1) && !lua_isstring(L, -1)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
			luaL_error(L, "resolve_host_address: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
			return 0;
		}
		else {
			const char * domain_name = lua_tostring(L, -2);
			const char * service_name = NULL;
			if (!lua_isnil(L, -1))
				service_name = lua_tostring(L, -1);

			addr_info_ptr_ptr = (struct addrinfo**)malloc(sizeof(struct addrinfo*));
			reqHandler->resolveHost(NULL, domain_name, service_name, addr_info_ptr_ptr);
		}

		return lua_yieldk(L, 0, (lua_KContext)addr_info_ptr_ptr, resolve_host_address_complete);
	}

	static int http_connection__gc(lua_State* L)
	{
		//DEBUGPOINT("HERE\n");
		EVHTTPClientSession* session = *(EVHTTPClientSession**)lua_touserdata(L, 1);
		delete session;
		/*
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		Poco::evnet::EVServer * server = reqHandler->getServerPtr();
		server->submitRequestForTaskExecutionNR(v_hello_world, 0);
		*/
		return 0;
	}

	static int make_http_connection_complete(lua_State* L, int status, lua_KContext ctx)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		EVHTTPClientSession *session = (EVHTTPClientSession*)ctx;

		//DEBUGPOINT("HERE %d\n", lua_gettop(L));

		Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
		if (usN.getRet() < 0) {
			delete session;
			char msg[1024];
			sprintf(msg, "make_http_connection: could not establish connection: %s", strerror(usN.getErrNo()));
			lua_pushnil(L);
			lua_pushstring(L, msg);

			return 2;
		}
		//DEBUGPOINT("HERE %d\n", lua_gettop(L));

		std::string meta_name = reqHandler->getDynamicMetaName();
		luaL_newmetatable(L, meta_name.c_str()); // Stack: meta
		luaL_newlib(L, dummy); // Stack: meta dummy
		lua_setfield(L, -2, "__index"); // Stack: meta
		lua_pushstring(L, "__gc"); // Stack: meta "__gc"
		lua_pushcfunction(L, http_connection__gc); // Stack: meta "__gc" fptr
		lua_settable(L, -3); // Stack: meta
		lua_pop(L, 1); // Stack:

		void * ptr = lua_newuserdata(L, sizeof(EVHTTPClientSession *)); //Stack: ptr
		*(EVHTTPClientSession **)ptr = session; //Stack: session
		luaL_setmetatable(L, meta_name.c_str()); // Stack: session
		lua_pushnil(L); // Stack session nil

		//DEBUGPOINT("HERE %d\n", lua_gettop(L));
		return 2;
	}

	static int make_http_connection_initiate(lua_State* L)
	{
		//DEBUGPOINT("HERE %d\n", lua_gettop(L));
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		EVHTTPClientSession *session = NULL;;
		if (lua_gettop(L) != 2) {
			luaL_error(L, "make_http_connection: invalid number of arguments, expected 2, actual %d ", lua_gettop(L));
			return 0;
		}
		else if (lua_isnil(L, -2) || !lua_isstring(L, -2)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
			luaL_error(L, "make_http_connection: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
			return 0;
		}
		else if (!lua_isnil(L, -1) && !lua_isstring(L, -1)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
			luaL_error(L, "make_http_connection: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
			return 0;
		}
		else {
			const char * server_address = lua_tostring(L, -2);
			int value = 0; lua_numbertointeger(lua_tonumber(L, -1), &value);
			unsigned short  port_num = (unsigned short)value;

			session = new EVHTTPClientSession();
			reqHandler->makeNewHTTPConnection(NULL, server_address, port_num, *session);
		}

		//DEBUGPOINT("HERE %p\n",session);
		return lua_yieldk(L, 0, (lua_KContext)session, make_http_connection_complete);
	}

	static int close_http_connection(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		EVHTTPClientSession *session = NULL;;
		if (lua_gettop(L) != 1) {
			luaL_error(L, "close_http_connection: invalid number of arguments, expected 2, actual %d ", lua_gettop(L));
			return 0;
		}
		if (!lua_isnil(L, -1) && !lua_isnumber(L, -1)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
			luaL_error(L, "close_http_connection: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
			return 0;
		}
		else {
			int value = 0; lua_numbertointeger(lua_tonumber(L, -1), &value);
			session = reqHandler->getHTTPConnection(value);
			if (!session) {
				luaL_error(L, "close_http_connection: invalid argumet %d", value);
				return 0;
			}
			reqHandler->closeHTTPSession(*session);
		}

		DEBUGPOINT("HERE %p\n",session);
		return 0;
	}

	static int req__gc(lua_State *L)
	{
		Net::HTTPRequest* request = *(Net::HTTPRequest**)lua_touserdata(L, 1);
		delete request;
		return 0;
	}

	static int new_request(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

		EVHTTPRequest* request = new EVHTTPRequest();

		std::string meta_name = reqHandler->getDynamicMetaName();
		luaL_newmetatable(L, meta_name.c_str()); // Stack: meta
		luaL_newlib(L, evpoco_httpreq_lib); // Stack: meta httpreq
		lua_setfield(L, -2, "__index"); // Stack: meta
		lua_pushstring(L, "__gc"); // Stack: meta "__gc"
		lua_pushcfunction(L, req__gc); // Stack: meta "__gc" fptr
		lua_settable(L, -3); // Stack: meta
		lua_pop(L, 1); // Stack: 

		void * ptr = lua_newuserdata(L, sizeof(EVHTTPRequest*));
		*(EVHTTPRequest**)ptr = request;
		luaL_setmetatable(L, meta_name.c_str());

		return 1;
	}

	// This is request header send
	static int send_request_header(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
			luaL_error(L, "send_request_header: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
			return 0;
		}
		else if (lua_isnil(L, 2) || !lua_isuserdata(L, 2)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
			luaL_error(L, "send_request_header: invalid second argumet %s", lua_typename(L, lua_type(L, 2)));
			return 0;
		}
		else {
			EVHTTPClientSession& session = *(*(EVHTTPClientSession**)lua_touserdata(L, 1));
			EVHTTPRequest & request = *(*(EVHTTPRequest**)lua_touserdata(L, 2));
			reqHandler->sendHTTPHeader(session, request);
		}
		return 0;
	}

	// This is request send
	static int send_request_body(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
			luaL_error(L, "send_request_body: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
			return 0;
		}
		else if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
			luaL_error(L, "send_request_body: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
			return 0;
		}
		else {
			EVHTTPClientSession& session = *(*(EVHTTPClientSession**)lua_touserdata(L, -2));
			EVHTTPRequest & request = *(*(EVHTTPRequest**)lua_touserdata(L, -1));
			reqHandler->sendHTTPRequestData(session, request);
		}
		return 0;
	}

	static int resp__gc(lua_State *L)
	{
		EVHTTPResponse* response = *(EVHTTPResponse**)lua_touserdata(L, 1);
		delete response;
		return 0;
	}

	static int receive_http_response_complete(lua_State* L, int status, lua_KContext ctx)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

		EVHTTPResponse* response = (EVHTTPResponse*)ctx;

		Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
		if (usN.getRet() < 0) {
			delete response;
			char msg[1024];
			sprintf(msg, "receive_http_response: error: %s", strerror(usN.getErrNo()));
			lua_pushstring(L, msg);

			return 1;
		}

		std::string meta_name = reqHandler->getDynamicMetaName();
		luaL_newmetatable(L, meta_name.c_str()); // Stack: meta
		luaL_newlib(L, evpoco_httpresp_lib); // Stack: meta evpoco_httpresp_lib
		lua_setfield(L, -2, "__index"); // Stack: meta
		lua_pushstring(L, "__gc"); // Stack: meta "__gc"
		lua_pushcfunction(L, resp__gc); // Stack: meta "__gc" fptr
		lua_settable(L, -3); // Stack: meta
		lua_pop(L, 1); // Stack:

		void * ptr = lua_newuserdata(L, sizeof(EVHTTPResponse*));
		*(EVHTTPResponse**)ptr = response;
		luaL_setmetatable(L, meta_name.c_str());

		return 1;
	}

	static int receive_http_response_initiate(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
			luaL_error(L, "send_request_header: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
			return 0;
		}
		EVHTTPClientSession& session = *(*(EVHTTPClientSession**)lua_touserdata(L, 1));
		EVHTTPResponse* response = new EVHTTPResponse();

		reqHandler->waitForHTTPResponse(NULL, (session), *response);
		return lua_yieldk(L, 0, (lua_KContext)response, receive_http_response_complete);
	}

	namespace httpmessage {
		static int set_version(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_version: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_version: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const char* value = lua_tostring(L, -1);
				if (!(*value)) {
					DEBUGPOINT("Here Invalid  value =%s\n", value);
					luaL_error(L, "set_version: Invalid value=%s", value);
					return 0;
				}
				message.setVersion(value);
			}
			return 0;
		}

		static int get_version(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				luaL_error(L, "get_version: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				std::string hdr_fld_value = message.getVersion();
				lua_pushstring(L, hdr_fld_value.c_str());
			}
			return 1;
		}

		static int set_chunked_trfencoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_chunked_trfencoding: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isboolean(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_chunked_trfencoding: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const int value = lua_toboolean(L, -1);
				message.setChunkedTransferEncoding(value);
			}
			return 0;
		}

		static int get_chunked_trfencoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_chunked_trfencoding: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				int hdr_fld_value = message.getChunkedTransferEncoding();
				lua_pushboolean(L, hdr_fld_value);
			}
			return 1;
		}

		static int set_content_length(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_content_length: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isinteger(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_content_length: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				int value = 0; lua_numbertointeger(lua_tonumber(L, -1), &value);
				message.setContentLength(value);
			}
			return 0;
		}

		static int get_content_length(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_content_length: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				int hdr_fld_value = message.getContentLength();
				lua_pushinteger(L, hdr_fld_value);
			}
			return 1;
		}

		static int set_trf_encoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_trf_encoding: invalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_trf_encoding: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const char* value = lua_tostring(L, -1);
				if (!(*value)) {
					DEBUGPOINT("Here Invalid value=%s\n", value);
					luaL_error(L, "set_trf_encoding: Invalid value=%s", value);
					return 0;
				}
				message.setTransferEncoding(value);
			}

			return 0;
		}

		static int get_trf_encoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_trf_encoding: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_pushstring(L, message.getTransferEncoding().c_str());
			}

			return 1;
		}

		static int set_content_type(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_content_type: invalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_content_type: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const char* value = lua_tostring(L, -1);
				if (!(*value)) {
					DEBUGPOINT("Here Invalid value=%s\n", value);
					luaL_error(L, "set_content_type: Invalid value=%s", value);
					return 0;
				}
				message.setContentType(value);
			}

			return 0;
		}

		static int get_content_type(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_content_type: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_pushstring(L, message.getContentType().c_str());
			}

			return 1;
		}

		static int set_keep_alive(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_keep_alive: invalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isboolean(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_keep_alive: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const int value = lua_tointeger(L, -1);
				message.setKeepAlive(value);
			}

			return 0;
		}

		static int get_keep_alive(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_keep_alive: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_pushboolean(L, message.getKeepAlive());
			}

			return 1;
		}

		static int set_hdr_field(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -3) || !lua_isuserdata(L, -3)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -3)));
				luaL_error(L, "set_hdr_field: invalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -2) || !lua_isstring(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_hdr_field: invalid second argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_hdr_field: invalid third argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -3));
				const char* name = lua_tostring(L, -2);
				const char* value = lua_tostring(L, -1);
				if (!(*name) || !(*value)) {
					DEBUGPOINT("Here Invalid (name=%s, value =%s)\n", name, value);
					luaL_error(L, "set_hdr_field: Invalid (name=%s, value=%s)", name, value);
					return 0;
				}
				message.set(name, value);
			}

			return 0;
		}

		static int get_hdr_field(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_hdr_field: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "get_hdr_field: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				lua_pushnil(L);
			}
			else {
				const char* hdr_fld_name = lua_tostring(L, -1);
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				std::string hdr_fld_value = message.get(hdr_fld_name, "");
				lua_pushstring(L, hdr_fld_value.c_str());
			}

			return 1;
		}

		static int get_hdr_fields(lua_State* L)
		{
			//DEBUGPOINT("Here\n");
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_hdr_fields: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_newtable (L);
				Poco::Net::NameValueCollection::ConstIterator it = message.begin();
				Poco::Net::NameValueCollection::ConstIterator end = message.end();
				for (; it != end; ++it) {
					lua_pushstring(L, it->second.c_str());
					lua_setfield(L, -2, it->first.c_str());
				}
			}

			return 1;
		}

		namespace httpreq {
			static int parse_form(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "parse_form: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					EVLHTTPPartHandler* partHandler = NULL;
					Net::HTMLForm *form = NULL;
					if (!reqHandler->getFromComponents(EVLHTTPRequestHandler::html_form)) {
						partHandler = new EVLHTTPPartHandler();
						try {
							form = new Net::HTMLForm(request, request.stream(), *partHandler);
						} catch (std::exception& ex) {
							DEBUGPOINT("CHA %s\n",ex.what());
							throw(ex);
						}
						reqHandler->addToComponents(EVLHTTPRequestHandler::html_form, form);
						reqHandler->addToComponents(EVLHTTPRequestHandler::part_handler, partHandler);
					}
					else {
						form = (Net::HTMLForm*)reqHandler->getFromComponents(EVLHTTPRequestHandler::html_form);
						partHandler = (EVLHTTPPartHandler*)reqHandler->getFromComponents(EVLHTTPRequestHandler::part_handler);
					}

					void * ptr = lua_newuserdata(L, sizeof(Net::HTMLForm*));
					*((Net::HTMLForm**)ptr) = form;
					luaL_setmetatable(L, _html_form_type_name);
				}

				return 1;
			}

			static int get_part_names(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_part_names: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -1));
					lua_newtable(L);
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)reqHandler->getFromComponents(EVLHTTPRequestHandler::part_handler);
					int i = 1;
					auto parts = ph->getParts();
					for (auto it = parts.begin(); it != parts.end(); ++it, i++) {
						lua_pushstring(L, it->first.c_str());
						lua_seti(L, -2, i);
					}
				}

				return 1;
			}

			static int get_part(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

				if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
					luaL_error(L, "get_part: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
					lua_pushnil(L);
				}
				else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_part: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -2));
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)reqHandler->getFromComponents(EVLHTTPRequestHandler::part_handler);
					std::string s = lua_tostring(L, -1);
				
					auto parts = ph->getParts();
					PartData * pd = parts[s];

					lua_newtable(L);

					lua_pushstring(L, "length");
					lua_pushinteger(L, pd->_length);
					lua_settable(L, -3);

					lua_pushstring(L, "type");
					lua_pushstring(L, pd->_type.c_str());
					lua_settable(L, -3);

					lua_pushstring(L, "name");
					lua_pushstring(L, pd->_name.c_str());
					lua_settable(L, -3);

					lua_pushstring(L, "data");
					lua_pushlightuserdata(L, &(pd->_cms));
					lua_settable(L, -3);

					lua_pushstring(L, "params");
					lua_newtable(L);
					for (auto it = pd->_params.begin(); it != pd->_params.end(); ++it) {
						lua_pushstring(L, it->first.c_str());
						lua_pushstring(L, it->second.c_str());
						lua_settable(L, -3);
					}
					lua_settable(L, -3);
				}

				return 1;
			}

			static int get_query_parameters(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_query_parameters: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -1));
					URI::QueryParameters qp;
					try {
						URI uri(request.getURI());
						qp = uri.getQueryParameters();
					} catch (std::exception ex) {
						luaL_error(L, "%s", ex.what());
						return 0;
					}
					lua_newtable(L);
					for (auto it = qp.begin(); it != qp.end(); ++it) {
						lua_pushstring(L, it->first.c_str());
						lua_pushstring(L, it->second.c_str());
						lua_settable(L, -3);
					}
				}

				return 1;
			}

			static int set_uri(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "set_uri: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "set_uri: invalid second argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, 1));
					const char* uri = lua_tostring(L, 2);
					request.setURI(uri);
				}

				return 0;
			}

			static int get_uri(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_uri: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -1));
					std::string uri = request.getURI();
					lua_pushstring(L, uri.c_str());
				}

				return 1;
			}

			static int get_method(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_method: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -1));
					std::string method = request.getMethod();
					lua_pushstring(L, method.c_str());
				}

				return 1;
			}

			static int set_method(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "set_method: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "set_method: invalid second argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, 1));
					const char* method = lua_tostring(L, 2);
					request.setMethod(method);
				}

				return 0;
			}

			static int get_host(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_host: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -1));
					std::string host = request.getHost();
					lua_pushstring(L, host.c_str());
				}

				return 1;
			}

			static int set_host(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "set_host: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "set_host: invalid second argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, 1));
					const char* host = lua_tostring(L, 2);
					request.setHost(host);
				}

				return 0;
			}

			static int set_expect_continue(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "set_expect_continue: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else if (lua_isnil(L, 2) || !lua_isboolean(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "set_expect_continue: invalid second argumet %s", lua_typename(L, lua_type(L, 1)));
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, 1));
					int expect_continue = lua_toboolean(L, 2);
					request.setExpectContinue(expect_continue);
				}

				return 0;
			}

			static int get_expect_continue(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_expect_continue: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPRequest& request = *(*(Net::HTTPRequest**)lua_touserdata(L, -1));
					int expect_continue = request.getExpectContinue();
					lua_pushboolean(L, expect_continue);
				}

				return 1;
			}

			static int write(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "ostream:write: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "ostream:write: invalid third argumet %s", lua_typename(L, lua_type(L, 2)));
				}
				else {
					EVHTTPRequest& request = *(*(EVHTTPRequest**)lua_touserdata(L, 1));
					std::ostream& ostr = *(request.getRequestStream());
					ostr << lua_tostring(L, 2);
					ostr << std::flush;
				}
				return 0;
			}

			static int read(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "istream:read: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, 1));
					std::istream& istr = request.stream();
					memset(reqHandler->getEphemeralBuf(), 0, EVL_EPH_BUFFER_SIZE);
					istr.read(reqHandler->getEphemeralBuf(), EVL_EPH_BUFFER_SIZE-1);
					size_t size = istr.gcount();
					if (size) lua_pushstring(L, reqHandler->getEphemeralBuf());
					else lua_pushnil(L);
				}
				return 1;
			}

			static int get_cookies(lua_State* L) {
				Poco::Net::NameValueCollection nvset;
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "istream:read: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, 1));
					request.getCookies(nvset);
					lua_newtable (L);
					for (auto it = nvset.begin(); it != nvset.end(); ++it) {
						lua_pushstring(L, it->first.c_str());
						lua_pushstring(L, it->second.c_str());
						lua_settable(L, -3);
					}
				}
				return 1;
			}

			namespace htmlform {
				static int get_form_field(lua_State* L)
				{
					//DEBUGPOINT("Here\n");
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					Net::HTTPRequest& request = reqHandler->getRequest();
					//DEBUGPOINT("Here\n");
					if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
						DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
						luaL_error(L, "get_form_field: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
					}
					else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
						DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
						luaL_error(L, "get_form_field: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
						lua_pushnil(L);
					}
					else {
						const char* fld_name = lua_tostring(L, -1);
						Net::HTMLForm* form = NULL;
						form =  *((Net::HTMLForm**)lua_touserdata(L, -2));
						std::string fld_value = form->get(fld_name, "");
						lua_pushstring(L, fld_value.c_str());
					}

					return 1;
				}

				static int begin_iteration(lua_State* L)
				{
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
						luaL_error(L, "begin_iteration: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
						lua_pushnil(L);
						lua_pushnil(L);
					}
					else {
						Net::HTMLForm* form = NULL;
						form = *((Net::HTMLForm**)lua_touserdata(L, -1));
						struct form_iterator * iter_ptr = (struct form_iterator *)lua_newuserdata(L, sizeof(struct form_iterator));

						iter_ptr->it = form->begin();
						iter_ptr->last = form->end();
						if (iter_ptr->it == iter_ptr->last) {
							lua_pop(L, 1);
							lua_pushnil(L);
							lua_pushnil(L);
							lua_pushnil(L);
						}
						else {
							lua_pushstring(L, iter_ptr->it->first.c_str());
							lua_pushstring(L, iter_ptr->it->second.c_str());
						}
					}

					return 3;
				}

				static int next_iteration(lua_State* L)
				{
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
						luaL_error(L, "next_iteration: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
						lua_pushnil(L);
					}
					else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
						luaL_error(L, "next_iteration: invalid first argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
						lua_pushnil(L);
					}
					else {
						Net::HTMLForm* form = NULL;

						form = *(Net::HTMLForm**)lua_touserdata(L, -2);
						struct form_iterator * iter_ptr = (struct form_iterator *)lua_touserdata(L, -1);

						++(iter_ptr->it);
						if (iter_ptr->it == iter_ptr->last) {
							lua_pushnil(L);
							lua_pushnil(L);
						}
						else {
							lua_pushstring(L, iter_ptr->it->first.c_str());
							lua_pushstring(L, iter_ptr->it->second.c_str());
						}
					}

					return 2;
				}

				static int empty(lua_State* L)
				{
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
						luaL_error(L, "begin_iteration: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
					}
					else {
						Net::HTMLForm* form = NULL;
						form = *((Net::HTMLForm**)lua_touserdata(L, -1));
						lua_pushboolean(L, form->empty());
					}
					return 1;
				}
			}
		}

		namespace httpresp {
			static int set_status(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				Net::HTTPServerResponse& response = reqHandler->getResponse();
				if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
					luaL_error(L, "set_status: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
					return 0;
				}
				else if (lua_isnil(L, -1) || !lua_isinteger(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "set_status: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
					return 0;
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, -2));
					int value = 100; lua_numbertointeger(lua_tonumber(L, -1), &value);
					response.setStatusAndReason((Net::HTTPResponse::HTTPStatus)value);
				}

				return 0;
			}

			static int set_date(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				Net::HTTPServerResponse& response = reqHandler->getResponse();
				if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
					luaL_error(L, "set_date: invalid first argumet %s", lua_typename(L, lua_type(L, -2)));
					return 0;
				}
				else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "set_date: invalid second argumet %s", lua_typename(L, lua_type(L, -1)));
					return 0;
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, -2));
					const char * value = lua_tostring(L, -1);
					if (!(*value)) {
						luaL_error(L, "set_date: invalid second argumet %s", lua_typename(L, lua_type(L, -2)));
						return 0;
					}
					try {
						int tzd;
						DateTime dt = DateTimeParser::parse(value, tzd);
						response.setDate(dt.timestamp());
					} catch (std::exception ex) {
						luaL_error(L, ex.what());
						return 0;
					}
				}

				return 0;
			}

			// This is response send
			static int send(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "set_date: invalid argumet %s", lua_typename(L, lua_type(L, -1)));
					return 0;
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, -1));
					std::ostream& ostr = response.send();
				}
				return 0;
			}

			static int write(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "ostream:write: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "ostream:write: invalid third argumet %s", lua_typename(L, lua_type(L, 2)));
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, 1));
					std::ostream& ostr = response.getOStream();
					ostr << lua_tostring(L, 2);
				}
				return 0;
			}

			static int read(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "istream:read: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else {
					EVHTTPResponse& response = *(*(EVHTTPResponse**)lua_touserdata(L, 1));
					std::istream& istr = *(response.getStream());
					memset(reqHandler->getEphemeralBuf(), 0, EVL_EPH_BUFFER_SIZE);
					istr.read(reqHandler->getEphemeralBuf(), EVL_EPH_BUFFER_SIZE-1);
					size_t size = istr.gcount();
					if (size) lua_pushstring(L, reqHandler->getEphemeralBuf());
					else lua_pushnil(L);
				}
				return 1;
			}

			static int get_cookies(lua_State* L) {
				std::vector<Net::HTTPCookie> cookies;
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "istream:read: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else {
					EVHTTPResponse& response = *(*(EVHTTPResponse**)lua_touserdata(L, 1));
					int i = 0;
					response.getCookies(cookies);
					lua_newtable (L);
					for (auto it = cookies.begin(); it != cookies.end(); ++it) {
						i++;
						lua_newtable(L);
						lua_pushstring(L, "version");
						lua_pushinteger(L, it->getVersion());
						lua_settable(L, -3);
						lua_pushstring(L, "name");
						lua_pushstring(L, it->getName().c_str());
						lua_settable(L, -3);
						lua_pushstring(L, "comment");
						lua_pushstring(L, it->getComment().c_str());
						lua_settable(L, -3);
						lua_pushstring(L, "domain");
						lua_pushstring(L, it->getDomain().c_str());
						lua_settable(L, -3);
						lua_pushstring(L, "path");
						lua_pushstring(L, it->getPath().c_str());
						lua_settable(L, -3);
						lua_pushstring(L, "priority");
						lua_pushstring(L, it->getPriority().c_str());
						lua_settable(L, -3);
						lua_pushstring(L, "secure");
						lua_pushboolean(L, it->getSecure());
						lua_settable(L, -3);
						lua_pushstring(L, "maxage");
						lua_pushinteger(L, it->getMaxAge());
						lua_settable(L, -3);
						lua_pushstring(L, "httponly");
						lua_pushboolean(L, it->getHttpOnly());
						lua_settable(L, -3);
						lua_seti(L, -2, i);
					}
				}
				return 1;
			}

		}
	}
}

static int luaopen_evpoco(lua_State* L)
{
	luaL_newlib(L, evpoco_lib); //Stack: context

	// Stack: context
	luaL_newmetatable(L, _http_req_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_httpreq_lib); // Stack: context meta httpreq
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	// Stack: context
	luaL_newmetatable(L, _http_resp_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_httpresp_lib); // Stack: context meta httpresp
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	// Stack: context
	luaL_newmetatable(L, _html_form_type_name); // Stack: context meta
	luaL_newlib(L, form_lib); // Stack: context meta form
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	return 1;
}

const std::string EVLHTTPRequestHandler::SERVER_PREFIX_CFG_NAME("evlhttprequesthandler.");
const std::string EVLHTTPRequestHandler::ENABLE_CACHE("enableluafilecache");

EVLHTTPRequestHandler::EVLHTTPRequestHandler():
	_L0(0),
	_L(0),
	_http_connection_count(-1),
	_variable_instance_count(0)
{
	*_ephemeral_buffer = 0;
	/*
	It is really not required to have _L0 and a new thread _L
	_L0 = luaL_newstate();
	luaL_openlibs(_L0);

	_L = lua_newthread(_L0);
	luaL_openlibs(_L);
	*/
	_L = luaL_newstate();
	luaL_openlibs(_L);

	lua_register(_L, "ev_sleep", evpoco::evpoco_sleep);
	luaL_requiref(_L, _platform_name, &luaopen_evpoco, 1);

	lua_pushlightuserdata(_L, (void*) this);
	lua_setglobal(_L, "EVLHTTPRequestHandler*");

	Poco::Util::AbstractConfiguration& config = appConfig();
	bool enable_lua_cache = config.getBool(SERVER_PREFIX_CFG_NAME + ENABLE_CACHE , true);

	//DEBUGPOINT("Here enable_lua_cache=%d\n", enable_lua_cache);
	if (enable_lua_cache) {
		lua_pushlightuserdata(_L, (void*)luaL_loadcachedbufferx);
		lua_setglobal(_L, LUA_CACHED_FILE_LOADER_FUNCTION);

		lua_pushlightuserdata(_L, (void*)luaL_cacheloadedfile);
		lua_setglobal(_L, LUA_FILE_CACHING_FUNCTION);

		lua_pushlightuserdata(_L, (void*)luaL_checkfilecacheexists);
		lua_setglobal(_L, LUA_CACHED_FILE_EXISTS_FUNCTION);

		lua_pushlightuserdata(_L, (void*)luaL_getcachedpath);
		lua_setglobal(_L, LUA_CACHED_PATH_FUNCTION);

		lua_pushlightuserdata(_L, (void*)luaL_addfilepathtocache);
		lua_setglobal(_L, LUA_ADDTO_CACHED_PATH_FUNCTION);
	}

}

EVLHTTPRequestHandler::~EVLHTTPRequestHandler()
{
	//lua_close(_L0);
    for ( std::map<mapped_item_type, void*>::iterator it = _components.begin(); it != _components.end(); ++it ) {
		switch (it->first) {
			case html_form:
				{
					Net::HTMLForm* form = (Net::HTMLForm*)it->second;
					delete form;
				}
				break;
			case part_handler:
				{
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)it->second;
					delete ph;
				}
				break;
			default:
				break;
		}
    }
    _components.clear();
    for ( std::map<int, EVHTTPClientSession*>::iterator it = _http_connections.begin(); it != _http_connections.end(); ++it ) {
		delete it->second;
	}
	_http_connections.clear();
}

void EVLHTTPRequestHandler::send_string_response(int line_no, const char* msg)
{
	Net::HTTPServerRequest& request = (getRequest());
	Net::HTTPServerResponse& response = (getResponse());

	response.setChunkedTransferEncoding(true);
	response.setContentType("text/plain");
	response.setContentType("text/plain");
	response.setStatus(Net::HTTPResponse::HTTP_BAD_REQUEST);
	std::ostream& ostr = getResponse().send();

	ostr << "EVLHTTPRequestHandler.cpp:" << line_no << ": " << msg << "\n";

	ostr.flush();
}

int EVLHTTPRequestHandler::deduceReqHandler()
{
	int status = 0;
	lua_getglobal(_L, "map_request_to_handler");
	if (lua_isnil(_L, -1)) {
		send_string_response(__LINE__, "map_request_to_handler: function not found");
		return -1;
	}
	status = lua_pcall(_L, 0, 2, 0); 
	if (LUA_OK != status) {
		DEBUGPOINT("Here %s\n", lua_tostring(_L, -1));
		return -1;
	}
	if (3 != lua_gettop(_L)) {
		DEBUGPOINT("Here number of return values%d\n", lua_gettop(_L));
		send_string_response(__LINE__, "map_request_to_handler: did not return values not OK");
		return -1;
	}
	if (lua_isnil(_L, -1) || !lua_isstring(_L, -1)) {
		send_string_response(__LINE__, "map_request_to_handler: did not return request handler function");
		return -1;
	}
	_request_handler_func = lua_tostring(_L, -1);
	if (lua_isnil(_L, -2) || !lua_isstring(_L, -2)) {
		send_string_response(__LINE__, "map_request_to_handler: did not return request handler");
		return -1;
	}
	_request_handler = lua_tostring(_L, -2);
	lua_pop(_L, 2);
	return 0;
}

int EVLHTTPRequestHandler::loadReqMapper()
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	int ret = luaL_dofile(_L, _mapping_script.c_str());
	if (0 != ret)
		send_string_response(__LINE__, lua_tostring(_L, -1));
	return ret;
}

int EVLHTTPRequestHandler::loadReqHandler()
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	int ret = luaL_dofile(_L, _request_handler.c_str());
	if (0 != ret)
		send_string_response(__LINE__, lua_tostring(_L, -1));
	return ret;
}

int EVLHTTPRequestHandler::handleRequest()
{
	int status = 0;
	/* Request object is necessary for deduction of script names
	 * Thus, it is not possible to do this initialization in the 
	 * constructor of this class.
	 * */
	if (INITIAL == getState()) {
		_mapping_script = getMappingScript(getRequest());
		if (0 != loadReqMapper()) {
			DEBUGPOINT("Here\n");
			return PROCESSING_ERROR;
		}
		if (0 != deduceReqHandler()) {
			//DEBUGPOINT("Here\n");
			return PROCESSING_ERROR;
		}
		if (0 != loadReqHandler()) {
			DEBUGPOINT("Here\n");
			return PROCESSING_ERROR;
		}
		lua_getglobal(_L, _request_handler_func.c_str());
		if (lua_isnil(_L, -1)) {
			DEBUGPOINT("Here\n");
			char s[100] = {};
			sprintf(s, "%s: function not found", _request_handler_func.c_str());
			send_string_response(__LINE__, s);
			return PROCESSING_ERROR;
		}
	}
	status = lua_resume(_L, NULL, 0);
	if ((LUA_OK != status) && (LUA_YIELD != status)) {
		DEBUGPOINT("HERE\n");
		if (getResponse().sent()) {
			std::ostream& ostr = getResponse().getOStream();
			ostr << "EVLHTTPRequestHandler.cpp:" << __LINE__ << ": " << lua_tostring(_L, -1) << "\n";
			ostr.flush();
		}
		else {
			send_string_response(__LINE__, lua_tostring(_L, -1));
		}
		return PROCESSING_ERROR;
	}
	else if (LUA_YIELD == status) {
		//DEBUGPOINT("HERE\n");
		return PROCESSING;
	}
	else {
		if (!lua_isnil(_L, -1) && lua_isstring(_L, -1)) {
			std::string output = lua_tostring(_L, -1);
			lua_pop(_L, 1);
			if (getResponse().sent()) {
				std::ostream& ostr = getResponse().getOStream();
				ostr << "EVLHTTPRequestHandler.cpp:" << __LINE__ << ": " << output.c_str() << "\r\n\r\n";
				ostr.flush();
			}
			else {
				send_string_response(__LINE__, output.c_str());
			}
		}
		lua_close(_L);
		return PROCESSING_COMPLETE;
	}
}

Poco::Util::AbstractConfiguration& EVLHTTPRequestHandler::appConfig()
{
	try
	{
		return Poco::Util::Application::instance().config();
	}
	catch (Poco::NullPointerException&)
	{
		throw Poco::IllegalStateException(
			"An application configuration is required to initialize the Poco::Net::SSLManager, "
			"but no Poco::Util::Application instance is available."
		);
	}
}


} } // namespace Poco::evnet
