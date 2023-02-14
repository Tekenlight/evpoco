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
#include <ifaddrs.h>
#include <netdb.h>
#include <pthread.h>
#include <atomic>
#include <errno.h>
#include <assert.h>

#include <ev_rwlock.h>
#include <chunked_memory_stream.h>

#include <ev_queue.h>

#include "Poco/Util/Application.h"
#include "Poco/evnet/EVTCPServer.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"
#include "Poco/evnet/EVHTTPResponse.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/CountingStream.h"
#include "Poco/NullStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/DateTimeParser.h"
#include "Poco/DateTime.h"
#include "Poco/URI.h"
//#include "Poco/Net/NetSSL.h"
//#include "Poco/Net/Context.h"

#include "Poco/evnet/evnet_lua.h"

struct _read_s {
	Poco::evnet::file_handle_p _fh;
	void * _buf;
	ssize_t _size;
	Poco::Net::StreamSocket * _ss_ptr;
	int _timeout;
};

struct _write_s {
	Poco::Net::StreamSocket * _ss_ptr;
	void * _buf;
	ssize_t _size;
	ssize_t _written;
	int _timeout;
};

extern "C" int socket_live(int fd);
extern int get_mail_message_funcs(lua_State *L);
extern int get_properties_funcs(lua_State *L);

namespace Poco {
namespace evnet {

const static char *_memory_buffer_name = "memorybuffer";
const static char *_file_handle_type_name = "filehandle";
const static char *_html_form_type_name = "htmlform";
const static char *_http_creq_type_name = "httpcreq";
const static char *_stream_socket_type_name = "streamsocket";
const static char *_ev_connected_socket_type_name = "evconnectedsocket";
const static char *_pooled_stream_socket_type_name = "pooled_streamsocket";
const static char *_http_sreq_type_name = "httpsreq";
const static char *_http_conn_type_name = "httpconn";
const static char *_http_sresp_type_name = "httpsresp";
const static char *_http_cresp_type_name = "httpcresp";
const static char *_platform_name = "platform";

const std::string EVLHTTPRequestHandler::SERVER_PREFIX_CFG_NAME("evlhttprequesthandler.");
const std::string EVLHTTPRequestHandler::ENABLE_CACHE("enableluafilecache");

const std::string EVLHTTPRequestHandler::PLATFORM_STR("evluaserver.");
const std::string EVLHTTPRequestHandler::PORT_STR("port");
const std::string EVLHTTPRequestHandler::NETWORKINTERFACETORUNON_STR("networkInterfaceToRunOn");

static int platform_name__tostring(lua_State *L)
{
	lua_pushstring(L, "platform");

	return 1;
}

static int http_cresp_type_name__tostring(lua_State *L)
{
	lua_pushstring(L, "httpcresp");

	return 1;
}

static int http_sresp_type_name__tostring(lua_State *L)
{
	lua_pushstring(L, "httpsresp");

	return 1;
}

static int http_conn_type_name__tostring(lua_State *L)
{
	EVHTTPClientSession * session = *(EVHTTPClientSession **)luaL_checkudata(L, 1, _http_conn_type_name);
	lua_pushfstring(L, "httpconn:[%p]", session);

	return 1;
}

static int http_sreq_type_name__tostring(lua_State *L)
{
	lua_pushstring(L, "httpsreq");

	return 1;
}

static int http_creq_type_name__tostring(lua_State *L)
{
	lua_pushstring(L, "httpcreq");

	return 1;
}

static int stream_sock_type_name__tostring(lua_State *L)
{
    void *sock = (void *)luaL_checkudata(L, 1, _stream_socket_type_name);
    lua_pushfstring(L, "%s:%p", _stream_socket_type_name, sock);

	return 1;
}

static int ev_connected_socket_type_name__tostring(lua_State *L)
{
    void *sock = (void *)luaL_checkudata(L, 1, _ev_connected_socket_type_name);
    lua_pushfstring(L, "%s:%p", _ev_connected_socket_type_name, sock);

	return 1;
}

static int html_form_type_name__tostring(lua_State *L)
{
	lua_pushstring(L, "htmlform");

	return 1;
}

static int file_handle_type_name__tostring(lua_State *L)
{
	lua_pushstring(L, "filehandle");

	return 1;
}

static int memory_buffer_name__tostring(lua_State *L)
{
	lua_pushstring(L, "memorybuffer");

	return 1;
}

namespace evpoco {
	static int evpoco_load_mail_message_funcs(lua_State* L);
	static int evpoco_load_properties_funcs(lua_State* L);
	static int evpoco_set_ws_recvd_msg_handler(lua_State* L);
	static int evpoco_get_ws_recvd_msg_handler(lua_State* L);
	static int evpoco_get_socket_upgrade_to(lua_State* L);
	static int evpoco_set_socket_upgrade_to(lua_State* L);
	static int evpoco_get_acc_sock_to_be_closed(lua_State* L);
	static int evpoco_set_acc_sock_to_be_closed(lua_State* L);
	static int get_accepted_stream_socket(lua_State* L);
	static int stop_taking_requests(lua_State* L);
	static int wait_all(lua_State* L);
	static int wait_initiate(lua_State* L);
	static int task_return_value(lua_State* L);
	static int get_http_request(lua_State* L);
	static int get_lua_state(lua_State* L);
	static int get_http_response(lua_State* L);
	static int resolve_host_address_complete(lua_State* L, int status, lua_KContext ctx);
	static int resolve_host_address_initiate(lua_State* L);
	static int get_host_ip_address_and_port(lua_State* L);
	static int make_http_connection_complete(lua_State* L, int status, lua_KContext ctx);
	static int make_http_connection_initiate(lua_State* L);
	static int make_tcp_connection_complete(lua_State* L, int status, lua_KContext ctx);
	static int make_tcp_connection_initiate(lua_State* L);
	static int stop_tracking_conn_sock(lua_State* L);
	static int use_pooled_connection(lua_State* L);
	static int set_socket_managed(lua_State* L);
	static int cleanup_stream_socket(lua_State* L);
	static int recv_data_from_socket_initiate(lua_State* L);
	static int recv_data_from_socket_complete(lua_State* L, int status, lua_KContext ctx);
	static int send_data_on_socket_initiate(lua_State* L);
	static int complete_send_data_on_socket(lua_State* L, int status, lua_KContext ctx);
	static int send_data_on_acc_socket(lua_State* L);
	static int send_data_on_acc_socket_complete(lua_State* L, int status, lua_KContext ctx);
	static int shutdown_websocket(lua_State* L);
	static int websocket_active(lua_State* L);
	static int debug_ss_ptr(lua_State* L);
	static int socket_active(lua_State* L);
	static int async_run_lua_script(lua_State* L);
	static int async_run_lua_script_singleton(lua_State* L);
	static int websocket_active_complete(lua_State* L, int status, lua_KContext ctx);
	static int track_ss_as_websocket(lua_State* L);
	static int track_ss_as_websocket_complete(lua_State* L, int status, lua_KContext ctx);
	static int ev_hibernation_initiate(lua_State* L);
	static int ev_dbg_pthread_self(lua_State* L);
	static int get_sock_fd(lua_State* L);
	static int ev_hibernation_complete(lua_State* L, int status, lua_KContext ctx);
	static int send_cms_on_socket_initiate(lua_State* L);
	static int complete_send_cms_on_socket(lua_State* L, int status, lua_KContext ctx);
	static int close_tcp_connection(lua_State* L);
	static int nb_make_http_connection_initiate(lua_State* L);
	static int nb_make_http_connection_complete(lua_State* L, long task_id, evl_async_task* tp);
	static int close_http_connection(lua_State* L);
	static int close_http_connection_finalize(lua_State* L, int status, lua_KContext ctx);
	static int new_request(lua_State* L);
	static int send_request_header(lua_State* L);
	static int send_request_body(lua_State* L);
	static int receive_http_response_initiate(lua_State* L);
	static int nb_subscribe_to_http_response(lua_State* L);
	static int nb_fetch_arrived_http_response(lua_State* L, long task_id, evl_async_task* tp);

	static int alloc_buffer(lua_State* L);
	static int ev_lua_file_open_initiate(lua_State* L);
	static int ev_lua_file_read_text_initiate(lua_State* L);
	static int ev_lua_file_read_binary_initiate(lua_State* L);
	static int ev_lua_file_read_binary_initiate_1(lua_State* L);
	static int ev_lua_file_write_text(lua_State* L);
	static int ev_lua_file_write_binary(lua_State* L);
	static int ev_lua_file_close(lua_State* L);
	static void validate_file_handle(lua_State* L);
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
			static int read_buff(lua_State* L);
			static int get_message_body_str(lua_State* L);
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
			static int get_status(lua_State* L);
			static int set_status(lua_State* L);
			static int set_date(lua_State* L);
			static int send(lua_State* L);
			static int write(lua_State* L);
			static int read(lua_State* L);
			static int read_buff(lua_State* L);
			static int get_message_body_str(lua_State* L);
			static int get_cookies(lua_State* L);
		}
	}
}

static const luaL_Reg dummy[] = {
	{ NULL, NULL }
};

static const luaL_Reg evpoco_file_lib[] = {
	{ "read_text", &evpoco::ev_lua_file_read_text_initiate},
	{ "read_binary", &evpoco::ev_lua_file_read_binary_initiate},
	{ "read_binary_1", &evpoco::ev_lua_file_read_binary_initiate_1},
	{ "write_text", &evpoco::ev_lua_file_write_text},
	{ "write_binary", &evpoco::ev_lua_file_write_binary},
	{ "close", &evpoco::ev_lua_file_close},
	{ NULL, NULL }
};

static const luaL_Reg form_lib[] = {
	{ "get_form_field", &evpoco::httpmessage::httpreq::htmlform::get_form_field },
	{ "begin_iteration", &evpoco::httpmessage::httpreq::htmlform::begin_iteration},
	{ "next_iteration", &evpoco::httpmessage::httpreq::htmlform::next_iteration},
	{ "empty", &evpoco::httpmessage::httpreq::htmlform::empty},
	{ NULL, NULL }
};

static const luaL_Reg evpoco_stream_sock_lib[] = {
	{ NULL, NULL }
};

static const luaL_Reg evpoco_ev_conn_stream_sock_lib[] = {
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
	{ "read_buff", &evpoco::httpmessage::httpreq::read_buff},
	{ "get_message_body_str", &evpoco::httpmessage::httpreq::get_message_body_str},
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
	{ "get_status", &evpoco::httpmessage::httpresp::get_status },
	{ "set_date", &evpoco::httpmessage::httpresp::set_date },
	{ "send", &evpoco::httpmessage::httpresp::send },
	{ "write", &evpoco::httpmessage::httpresp::write },
	{ "read", &evpoco::httpmessage::httpresp::read },
	{ "read_buff", &evpoco::httpmessage::httpresp::read_buff },
	{ "get_message_body_str", &evpoco::httpmessage::httpresp::get_message_body_str},
	{ "get_cookies", &evpoco::httpmessage::httpresp::get_cookies },
	{ NULL, NULL }
};

static const luaL_Reg evpoco_lib[] = {
	{ "debug_ss_ptr", &evpoco::debug_ss_ptr},
	{ "socket_active", &evpoco::socket_active},
	{ "wait", &evpoco::wait_initiate },
	{ "task_return_value", &evpoco::task_return_value },
	{ "get_http_request", &evpoco::get_http_request },
	{ "get_http_response", &evpoco::get_http_response },
	{ "get_host_ip_address_and_port", &evpoco::get_host_ip_address_and_port },
	{ "resolve_host_address", &evpoco::resolve_host_address_initiate },
	{ "make_http_connection", &evpoco::make_http_connection_initiate },
	{ "make_tcp_connection", &evpoco::make_tcp_connection_initiate },
	{ "stop_tracking_conn_sock", &evpoco::stop_tracking_conn_sock },
	//{ "use_pooled_connection", &evpoco::use_pooled_connection },
	//{ "set_socket_managed", &evpoco::set_socket_managed },
	//{ "cleanup_stream_socket", &evpoco::cleanup_stream_socket },
	{ "close_tcp_connection", &evpoco::close_tcp_connection },
	{ "recv_data_from_socket", &evpoco::recv_data_from_socket_initiate },
	{ "send_data_on_socket", &evpoco::send_data_on_socket_initiate },
	{ "send_data_on_acc_socket", &evpoco::send_data_on_acc_socket},
	{ "shutdown_websocket", &evpoco::shutdown_websocket},
	{ "websocket_active", &evpoco::websocket_active},
	{ "async_run_lua_script", &evpoco::async_run_lua_script},
	{ "async_run_lua_script_singleton", &evpoco::async_run_lua_script_singleton},
	{ "track_ss_as_websocket", &evpoco::track_ss_as_websocket},
	{ "ev_hibernate", &evpoco::ev_hibernation_initiate},
	{ "ev_dbg_pthread_self", &evpoco::ev_dbg_pthread_self},
	{ "get_sock_fd", &evpoco::get_sock_fd},
	{ "send_cms_on_socket", &evpoco::send_cms_on_socket_initiate },
	{ "nb_make_http_connection", &evpoco::nb_make_http_connection_initiate },
	{ "close_http_connection", &evpoco::close_http_connection},
	{ "new_request", &evpoco::new_request},
	{ "send_request_header", &evpoco::send_request_header },
	{ "send_request_body", &evpoco::send_request_body },
	{ "receive_http_response", &evpoco::receive_http_response_initiate },
	{ "subscribe_to_http_response", &evpoco::nb_subscribe_to_http_response },
	{ "file_open", &evpoco::ev_lua_file_open_initiate },
	{ "alloc_buffer", &evpoco::alloc_buffer },
	{ "get_lua_state", &evpoco::get_lua_state },
	{ "mail_message_funcs", &evpoco::evpoco_load_mail_message_funcs },
	{ "properties_funcs", &evpoco::evpoco_load_properties_funcs },
	{ "set_ws_recvd_msg_handler", &evpoco::evpoco_set_ws_recvd_msg_handler },
	{ "get_ws_recvd_msg_handler", &evpoco::evpoco_get_ws_recvd_msg_handler },
	{ "set_socket_upgrade_to", &evpoco::evpoco_set_socket_upgrade_to },
	{ "get_socket_upgrade_to", &evpoco::evpoco_get_socket_upgrade_to },
	{ "get_acc_sock_to_be_closed", &evpoco::evpoco_get_acc_sock_to_be_closed },
	{ "set_acc_sock_to_be_closed", &evpoco::evpoco_set_acc_sock_to_be_closed },
	{ "get_accepted_stream_socket", &evpoco::get_accepted_stream_socket},
	{ "stop_taking_requests", &evpoco::stop_taking_requests},
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

evl_pool EVLHTTPRequestHandler::_pool;
evl_pool* EVLHTTPRequestHandler::getPool()
{
	evl_pool* ret =  &_pool;
	return ret;
}
std::map<std::string, void*> EVLHTTPRequestHandler::_map_of_maps;
std::map<std::string, void*> * EVLHTTPRequestHandler::getMapOfMaps()
{
	return &_map_of_maps;
}

/*
std::atomic<std::uintmax_t> EVLHTTPRequestHandler::_cached_stmt_id(0);
unsigned long EVLHTTPRequestHandler::getNextCachedStmtId()
{
	unsigned long l = 1;
	unsigned long value = std::atomic_fetch_add(&_cached_stmt_id, l);
	return value;
}
*/

static LUAFileCache sg_file_cache;

class LUAStateCache {
public:
	ev_queue_type _queue;
	LUAStateCache() {
		//DEBUGPOINT("Constructor\n");
		_queue = create_ev_queue();
	}
	~LUAStateCache() {
		lua_State* l = NULL;
		while ((l = (lua_State*)dequeue(_queue)) != NULL) {
			DEBUGPOINT("LUAStateCache Destructor\n");
			lua_close(l);
		}
		destroy_ev_queue(_queue);
	}
};

static LUAStateCache sg_lua_state_cache;

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

static chunked_memory_stream* get_cached_lua_file(lua_State *L, const char *name)
{
	chunked_memory_stream *cms = NULL;
	ev_rwlock_rdlock(sg_file_cache.cached_files_lock);
	auto it = sg_file_cache.cached_files.find(name);
	if (sg_file_cache.cached_files.end() != it)
		cms = sg_file_cache.cached_files[name];
	ev_rwlock_rdunlock(sg_file_cache.cached_files_lock);
	return cms;
}

static int luaL_checkfilecacheexists(lua_State *L, const char *name)
{
	chunked_memory_stream *cms = get_cached_lua_file(L, name);
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
		static int i = 0;
		i++;
		return LUA_OK;
	}
	chunked_memory_stream * cms = new chunked_memory_stream();
	LoadS ls ;
	ls._cms = cms;
	ls._buffer_node = NULL;
	ls._size=0;
	if (0 != lua_dump(L, (lua_Writer)cacheCB, (void*)&ls, 0)) {
		delete cms;
		return LUA_ERRRUN;
	}

	if (!get_cached_lua_file(L, name)) {
		//DEBUGPOINT("CHACHE_REQ:Here caching %s\n", name);
		ev_rwlock_wrlock(sg_file_cache.cached_files_lock);
		if (sg_file_cache.cached_files.end() == sg_file_cache.cached_files.find(name))
			sg_file_cache.cached_files[name] = cms;
		else
			delete cms;
		ev_rwlock_wrunlock(sg_file_cache.cached_files_lock);
	}
	else {
		//DEBUGPOINT("CHACHE_REQ:Here deleting cms due to concurrency !!!\n");
		delete cms;
	}
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
	ls._cms = get_cached_lua_file(L, name);
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

static int buffer__gc(lua_State *L)
{
	void * ptr = lua_touserdata(L, 1);
	void * buffer = *(void**)ptr;
	free(buffer);
	return 0;
}

static int obj__gc(lua_State *L)
{
	return 0;
}

namespace evpoco {

static int evpoco_load_mail_message_funcs(lua_State* L)
{
	return get_mail_message_funcs(L);
}

static int evpoco_load_properties_funcs(lua_State* L)
{
	return get_properties_funcs(L);
}

static int stop_taking_requests(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	reqHandler->stopTakingRequests();

	return 0;
}

static int get_accepted_stream_socket(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = reqHandler->getAcceptedSocket()->getStreamSocketPtr();

	//DEBUGPOINT("[%p]manaded = [%d]\n", ss_ptr, ss_ptr->impl()->isManaged());
	void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
	*(Poco::Net::StreamSocket**)ptr = new StreamSocket();
	*(*(Poco::Net::StreamSocket**)ptr) = *ss_ptr;
	luaL_setmetatable(L, _stream_socket_type_name);

	return 1;
}

static int evpoco_get_acc_sock_to_be_closed(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	bool s = (reqHandler->getAcceptedSocket()->getCLState());

	lua_pushboolean(L, s);
	return 1;
}

static int evpoco_set_acc_sock_to_be_closed(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	reqHandler->getAcceptedSocket()->setCLState(true);
	return 0;
}

static int evpoco_get_socket_upgrade_to(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	EVAcceptedStreamSocket::socket_upgrade_to_enum s = (reqHandler->getAcceptedSocket()->getSockUpgradeTo());

	lua_pushinteger(L, s);
	return 1;
}

static int evpoco_set_socket_upgrade_to(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_gettop(L) != 1) {
		luaL_error(L, "evpoco_set_socket_upgrade_to: Number of parameters expected: 1");
		return 1;
	}
	if (!lua_isinteger(L, 1)) {
		luaL_error(L, "evpoco_set_socket_upgrade_to: Invalid datatype of argument (integer expected)");
		return 1;
	}
	int u = lua_tointeger(L, 1);
	if (u != EVAcceptedStreamSocket::WEBSOCKET) {
		luaL_error(L, "evpoco_set_socket_upgrade_to: Invalid argument (only websocket [%d] supported)",
											EVAcceptedStreamSocket::WEBSOCKET);
		return 1;
	}
	reqHandler->getAcceptedSocket()->setSockUpgradeTo((EVAcceptedStreamSocket::socket_upgrade_to_enum)u);
	return 0;
}

static int evpoco_get_ws_recvd_msg_handler(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	std::string s = (reqHandler->getAcceptedSocket()->getWsRecvdMsgHandler());

	if (!s.c_str() || !strcmp(s.c_str(), ""))
		lua_pushnil(L);
	else
		lua_pushstring(L, s.c_str());
	return 1;
}

static int evpoco_set_ws_recvd_msg_handler(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_gettop(L) != 1) {
		luaL_error(L, "evpoco_set_ws_recvd_msg_handler: Number of parameters expected: 1");
		return 1;
	}
	if (!lua_isstring(L, 1)) {
		luaL_error(L, "evpoco_set_ws_recvd_msg_handler: Invalid datatype of argument (string expected)");
		return 1;
	}
	reqHandler->getAcceptedSocket()->setWsRecvdMsgHandler(std::string(lua_tostring(L, 1)));
	return 0;
}

static int evpoco_getmtname(lua_State* L)
{
	if (lua_gettop(L) != 1) {
		lua_pushnil(L);
		lua_pushstring(L, "ev_getmtname: Number of parameters expected: 1");
		return 2;
	}
	else if (!lua_isuserdata(L, 1)) {
		lua_pushnil(L);
		lua_pushstring(L, "ev_getmtname: Passed parameter should be user data");
		return 2;
	}
	lua_getmetatable(L, 1);
    lua_pushstring(L, "__name");
    lua_rawget(L, 2);
    return 1;
}

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

struct task_status_track_s {
	int    n;
	long*  la;
};

static int wait_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();

	long task_id = -1;
	struct task_status_track_s* tsp = (struct task_status_track_s*)ctx;
	if (tsp) {
		/* Conditions where a specific lis of tasks is being waited for.
		 * */
		long *la = tsp->la;
		int n = tsp->n;
		free(tsp);
		tsp = NULL;
		for (int i = 0; i <n; i++) {
			if(la[i] == usN.getRefSRNum()) {
				task_id = la[i];
				free(la);
			}
		}
	}
	else {
		/* Case where any task completion is being waited for. */
		task_id = usN.getRefSRNum();
	}

	if (-1 != task_id) {
		reqHandler->set_async_task_tracking(task_id, evl_async_task::COMPLETE);
		reqHandler->setAsyncTaskAwaited(false);
		lua_pushinteger(L, task_id);
		return 1;
	}
	else {
		/*
		 * Situation where a specific list of tasks is submitted for poll.
		 * And the completing task is not one of them.
		 * */

		return lua_yieldk(L, 0, (lua_KContext)tsp, wait_complete);
	}
}

/*
 * Here the logic is to check if there is a completed task and return the same
 * else wait for any task to complete and return it.
 * */
static int wait_any_initiate(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	EVLHTTPRequestHandler::async_tasks_t& tasks = reqHandler->getAsyncTaskList();

	int n = 0;
	Poco::evnet::EVEventNotification* usN = NULL;
	for (auto it = tasks.begin(); it != tasks.end(); ++it) {
		usN = NULL;
		if (((usN = reqHandler->get_async_task_notification(it->first)) != NULL) &&
			 (reqHandler->get_async_task_status(it->first) == evl_async_task::SUBMITTED)) {

			reqHandler->set_async_task_tracking(it->first, evl_async_task::COMPLETE);
			lua_pushinteger(L, it->first);
			DEBUGPOINT("Here task_id = %ld\n", it->first);
			return 1;
		}
		if (it->second->_task_tracking_state == evl_async_task::SUBMITTED) {
			n++;
		}
	}

	if (!n) {
		luaL_error(L, "wait: Nothing to wait for");;
		return 0;
	}

	reqHandler->setAsyncTaskAwaited(true);
	return lua_yieldk(L, 0, (lua_KContext)0, wait_complete);

}

static int wait_initiate(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);

	if (n > 1) {
		luaL_error(L, "wait: Invalid number of parameters %d", n);
		return 0;
	}

	if (n == 0) {
		return wait_any_initiate(L);
	}

	if (!lua_istable(L, 1)) {
		return luaL_error(L, "wait: either empty or a table of task ids expected as input");
		//return 0;
	}

	n = 1;
	lua_geti(L, 1, n);
	while (!lua_isnil(L, -1)) {
		if (!lua_isinteger(L, -1)) {
			luaL_error(L, "wait: only integer task ids allowed as input");
			return 0;
		}
		lua_pop(L, 1);
		n++;
		lua_geti(L, 1, n);
	}
	lua_pop(L, 1);

	int count = 0;
	evl_async_task* tp = NULL; 
	for (int i = 0; i < n ; i++) {
		lua_geti(L, 1,  i+1);
		long task_id = lua_tointeger(L, -1);
		lua_pop(L, 1);
		tp = reqHandler->get_async_task(task_id);
		if (tp != NULL) {
			count++;
		}
	}

	if (count == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "wait: Nothing to wait for");
		return 2;
	}

	long * la = (long*)malloc(count * sizeof(long));
	memset(la, 0, count * sizeof(long));
	tp = NULL; 
	int j = 0;
	for (int i = 0; i < n ; i++) {
		lua_geti(L, 1, i+1);
		long task_id = lua_tointeger(L, -1);
		lua_pop(L, 1);
		tp = reqHandler->get_async_task(task_id);
		if (tp != NULL) {
			la[j] = task_id;
			j++;
		}
	}
	n = count;

	Poco::evnet::EVEventNotification* usN = NULL;
	for (int i = 0; i < n ; i++) {
		long task_id = la[i];
		if (((usN = reqHandler->get_async_task_notification(task_id)) != NULL) &&
			 (reqHandler->get_async_task_status(task_id) == evl_async_task::SUBMITTED)) {

			DEBUGPOINT("Here task_id = %ld\n", task_id);
			reqHandler->set_async_task_tracking(task_id, evl_async_task::COMPLETE);
			lua_pushinteger(L, task_id);
			free(la);
			return 1;
		}
	}

	reqHandler->setAsyncTaskAwaited(true);

	struct task_status_track_s* tsp = (struct task_status_track_s*)malloc(sizeof(struct task_status_track_s));
	tsp->n = n;
	tsp->la = la;

	return lua_yieldk(L, 0, (lua_KContext)tsp, wait_complete);
}

static int wait_all(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	return 0;
}

static int get_http_request(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Net::HTTPServerRequest* requestPtr = reqHandler->getHTTPRequestPtr();
	if (requestPtr == NULL) {
		luaL_error(L, "HTTP Request not available");
	}

	Net::HTTPServerRequest& request = *requestPtr;

	void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerRequest*));
	*(Net::HTTPServerRequest**)ptr = &request;
	luaL_setmetatable(L, _http_sreq_type_name);

	return 1;
}

static int get_lua_state(lua_State* L)
{
	lua_pushlightuserdata(L, L);
	return 1;
}

static int get_http_response(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Net::HTTPServerResponse* responsePtr = reqHandler->getHTTPResponsePtr();
	if (responsePtr == NULL) {
		luaL_error(L, "Response handle is not available");
	}
	Net::HTTPServerResponse& response = *responsePtr;

	void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerResponse*));
	*(Net::HTTPServerResponse**)ptr = &response;
	luaL_setmetatable(L, _http_sresp_type_name);

	return 1;
}

static int resolve_host_address_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	struct addrinfo** addr_info_ptr_ptr = (struct addrinfo**)ctx;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getHRRet() != 0) {
		if (usN.getAddrInfo()) {
			//DEBUGPOINT("Here\n");
			usN.setAddrInfo(NULL);
			freeaddrinfo(usN.getAddrInfo());
		}
		//DEBUGPOINT("Here\n");
		free(addr_info_ptr_ptr);
		luaL_error(L, "resolve_host_address: address resolution could not happen: %s", gai_strerror(usN.getHRRet()));
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
	usN.setAddrInfo(NULL);
	free(addr_info_ptr_ptr);

	return 1;
}

static int get_host_ip_address_and_port(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	char hostIPAddress[INET_ADDRSTRLEN+1];
	struct ifaddrs * ifAddrStruct=NULL;
	struct ifaddrs * ifa=NULL;
	void * tmpAddrPtr=NULL;

	Poco::Util::AbstractConfiguration& config = reqHandler->appConfig();

	std::string prop_value = config.getString(reqHandler->PLATFORM_STR + reqHandler->NETWORKINTERFACETORUNON_STR);
	std::string port = config.getString(reqHandler->PLATFORM_STR + reqHandler->PORT_STR, "9980");

	memset(hostIPAddress, 0, (INET_ADDRSTRLEN+1));
	getifaddrs(&ifAddrStruct);

	for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) {
			continue;
		}
		if ((ifa->ifa_addr->sa_family == AF_INET) && // check it is IP4
			(strstr(prop_value.c_str(), ifa->ifa_name))) {
			// is a valid IP4 Address
			tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, hostIPAddress, INET_ADDRSTRLEN);
			if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

			lua_pushstring(L, hostIPAddress);
			lua_pushstring(L, port.c_str());
			break;
		}
	}

	return 2;
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

static int ss__gc(lua_State *L)
{
	Poco::Net::StreamSocket* ss_ptr = *(Poco::Net::StreamSocket**)lua_touserdata(L, 1);
	int fd = ss_ptr->impl()->sockfd();
	//DEBUGPOINT("HERE [%p]  fd=[%d]\n", ss_ptr, ss_ptr->impl()->sockfd());
	//if (!(ss_ptr->impl()->isManaged())) {
		//DEBUGPOINT("HERE\n");
		delete ss_ptr;
	//}
	//DEBUGPOINT("HERE\n");
	//DEBUGPOINT("Here socket[%d] live = [%d]\n", fd, socket_live(fd));
	return 0;
}

static int ev_connected_socket_type_name__gc(lua_State* L)
{
	EVConnectedStreamSocket* cn = *(EVConnectedStreamSocket**)luaL_checkudata(L, 1, _ev_connected_socket_type_name);
	int fd = cn->getSockfd();
	//DEBUGPOINT("CLEANING UP cn=[%p] fd=[%d]\n", cn, cn->getSockfd());
	delete cn;
	//DEBUGPOINT("Here socket[%d] live = [%d]\n", fd, socket_live(fd));

	return 0;
}

static int http_connection__gc(lua_State* L)
{
	EVHTTPClientSession* session = *(EVHTTPClientSession**)lua_touserdata(L, 1);
	//DEBUGPOINT("HERE sock = [%d]\n", session->getSS().impl()->sockfd());
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

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() < 0) {
		delete session;
		if (usN.getConnSock()) delete usN.getConnSock();
		char msg[1024];
		sprintf(msg, "make_http_connection: could not establish connection: %s", strerror(usN.getErrNo()));
		lua_pushnil(L);
		lua_pushstring(L, msg);
		lua_pushnil(L);
		luaL_error(L, msg);

		return 3;
	}
	if (usN.getHRRet() != 0) {
		delete session;
		if (usN.getConnSock()) delete usN.getConnSock();
		char msg[1024];
		sprintf(msg, "make_http_connection: could not establish connection: %s", gai_strerror(usN.getHRRet()));
		lua_pushnil(L);
		lua_pushstring(L, msg);
		lua_pushnil(L);
		luaL_error(L, msg);

		return 3;
	}
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));

	session->setConnSock(usN.getConnSock());
	void * ptr = lua_newuserdata(L, sizeof(EVHTTPClientSession *)); //Stack: ptr
	*(EVHTTPClientSession **)ptr = session; //Stack: session
	luaL_setmetatable(L, _http_conn_type_name); // Stack: session
	lua_pushnil(L); // Stack session nil
					// nil in lieu of msg (message, srcond return value)

	{
		Poco::Net::StreamSocket * ss_ptr = new StreamSocket(session->getSS());
		//*(ss_ptr) = session->getSS();
		void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
		*(Poco::Net::StreamSocket**)ptr = ss_ptr;
		luaL_setmetatable(L, _stream_socket_type_name);
	}
	{
		EVConnectedStreamSocket* cn = usN.getConnSock();
		void * ptr = lua_newuserdata(L, sizeof(EVConnectedStreamSocket*));
		*(void**)ptr = (void*)cn;
		luaL_setmetatable(L, _ev_connected_socket_type_name);
	}

	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	return 4;
}

static int make_http_connection_initiate(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	EVHTTPClientSession *session = NULL;;
	if (lua_gettop(L) < 2) {
		luaL_error(L, "make_http_connection: invalid number of arguments, expected 2, actual %d ", lua_gettop(L));
		return 0;
	}
	else if (lua_isnil(L, 1) || !lua_isstring(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "make_http_connection: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else if (!lua_isnil(L, 2) && !lua_isstring(L, 2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
		luaL_error(L, "make_http_connection: invalid second argumet %s", lua_typename(L, lua_type(L, 2)));
		return 0;
	}
	else {
		int timeout = -1;
		if (lua_gettop(L) > 2) {
			timeout = luaL_checkinteger(L, 3);
		}
		const char * server_address = lua_tostring(L, 1);
		int value = 0; lua_numbertointeger(lua_tonumber(L, 2), &value);
		unsigned short  port_num = (unsigned short)value;

		session = new EVHTTPClientSession();

		//DEBUGPOINT("Here ssp = [%p]\n", &(session->getSS()));
		reqHandler->makeNewHTTPConnection(NULL, server_address, port_num, *session, timeout);
	}

	return lua_yieldk(L, 0, (lua_KContext)session, make_http_connection_complete);
}

static int make_tcp_connection_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	//DEBUGPOINT("HERE %d\n", lua_gettop(L));

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() < 0) {
		if (usN.getConnSock()) delete usN.getConnSock();
		char msg[1024];
		sprintf(msg, "make_tcp_connection: could not establish connection: %s", strerror(usN.getErrNo()));
		lua_pushnil(L);
		lua_pushstring(L, msg);

		return 2;
	}
	if (usN.getHRRet() != 0) {
		if (usN.getConnSock()) delete usN.getConnSock();
		char msg[1024];
		sprintf(msg, "make_tcp_connection: could not establish connection: %s", gai_strerror(usN.getHRRet()));
		lua_pushnil(L);
		lua_pushstring(L, msg);
		luaL_error(L, msg);

		return 2;
	}

	/*
	 * Since this Socket can be pooled etc...
	 * It should have a standalone existence
	 */
	Poco::Net::StreamSocket * ss_ptr = new StreamSocket();
	ss_ptr->setFd(usN.sockfd());
	ss_ptr->setBlocking(false);

	{
		void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
		*(Poco::Net::StreamSocket**)ptr = ss_ptr;
		luaL_setmetatable(L, _stream_socket_type_name);
	}
	{
		EVConnectedStreamSocket* cn = usN.getConnSock();
		void * ptr = lua_newuserdata(L, sizeof(EVConnectedStreamSocket*));
		*(void**)ptr = (void*)cn;
		luaL_setmetatable(L, _ev_connected_socket_type_name);
	}

	//DEBUGPOINT("HERE valid socket that can get data in blocking mode for sure %d\n", usN.sockfd());
	return 2;
}

static int stop_tracking_conn_sock_complete(lua_State* L, int status, lua_KContext ctx)
{
	Poco::Net::StreamSocket * ss_ptr = (Poco::Net::StreamSocket*)ctx;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	int active = socket_live(ss_ptr->impl()->sockfd());
	//DEBUGPOINT("fd = [%d] active = [%d]\n", ss_ptr->impl()->sockfd(), active);

	return 0;
}

static int stop_tracking_conn_sock(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);

	reqHandler->stopTrackingConnSock(*ss_ptr);
	return lua_yieldk(L, 0, (lua_KContext)ss_ptr, stop_tracking_conn_sock_complete);
}

static int make_tcp_connection_initiate(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_gettop(L) < 2) {
		luaL_error(L, "make_tcp_connection: invalid number of arguments, expected 2 or 3, actual %d ", lua_gettop(L));
		return 0;
	}
	else if (lua_isnil(L, 1) || !lua_isstring(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "make_tcp_connection: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
		luaL_error(L, "make_tcp_connection: invalid second argumet %s", lua_typename(L, lua_type(L, 2)));
		return 0;
	}
	else {
		const char * server_address = lua_tostring(L, 1);
		int value = 0; lua_numbertointeger(lua_tonumber(L, 2), &value);
		unsigned short  port_num = (unsigned short)value;
		int timeout = -1;
		if (lua_gettop(L) > 2) {
			timeout = luaL_checkinteger(L, 3);
		}

		reqHandler->makeNewSocketConnection(NULL, server_address, port_num, timeout);
		//DEBUGPOINT("Here %s:%d\n", server_address, port_num);
	}
	//DEBUGPOINT("Here\n");

	return lua_yieldk(L, 0, (lua_KContext)0, make_tcp_connection_complete);
}

#if 0
static int set_socket_managed(lua_State* L)
{
	bool managed = false;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	luaL_checktype(L, 2, LUA_TBOOLEAN);
	managed = (lua_toboolean(L, 2))?true:false;

	ss_ptr->impl()->managed(managed);

	return 0;
}
#endif

#if 0
static int cleanup_stream_socket(lua_State* L)
{
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);

	/* Set the managed flag of ss_ptr to false so that
	 * the corresponding __gc will delete the object.
	 */
	//DEBUGPOINT("HERE\n");
	//ss_ptr->impl()->managed(false);

	return 0;
}
#endif

#if 0
static int use_pooled_connection(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	Poco::Net::StreamSocket * ss_ptr = (Poco::Net::StreamSocket *)lua_touserdata(L, 1);
	if (ss_ptr == NULL) {
		luaL_error(L, "Invlaid inputs to function : use_pooled_connection");
		return 0;
	}
	if (!(ss_ptr->impl()->isManaged())) {
		luaL_error(L, "The input socket is not managed by the caller: use_pooled_connection");
		return 0;
	}

	void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
	*(Poco::Net::StreamSocket**)ptr = ss_ptr;
	luaL_setmetatable(L, _stream_socket_type_name);

	return 1;
}
#endif

static int close_tcp_connection(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);

	ss_ptr->impl()->close();

	return 0;
}

//#define MANAGED(ss_ptr) (ss_ptr)->impl()->isManaged()
#define MANAGED(ss_ptr) 0

static int recv_data_from_socket_complete(lua_State* L, int status, lua_KContext ctx)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	struct _read_s* rp = (struct _read_s*)ctx;
	int wait_mode = 0;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() < 0) {
		DEBUGPOINT("Here usN.getRet() = [%ld] error=[%s]\n", usN.getRet(), strerror(usN.getErrNo()));
		DEBUGPOINT("Here fd = [%d]\n", rp->_ss_ptr->impl()->sockfd());
		free(rp);
		return luaL_error(L, "recv_data_from_socket: Failed to receive data from socket : %s", strerror(usN.getErrNo()));
	}

	long ret = EVTCPServer::receiveData(*(rp->_ss_ptr), rp->_buf, rp->_size, &wait_mode);
	if (ret < 0) {
		DEBUGPOINT("Here fd=[%d] ret=[%ld] {%d:%s}\n", rp->_ss_ptr->impl()->sockfd(), ret, errno, strerror(errno));
		free(rp);
		return luaL_error(L, "recv_data_from_socket: Failed to receive data from socket : %s", strerror(errno));
	}
	else if (ret == 0) {
		if (wait_mode == -2) {
			reqHandler->pollSocketForReadOrWrite(NULL, rp->_ss_ptr->impl()->sockfd(),
												Poco::evnet::EVLHTTPRequestHandler::WRITE, rp->_timeout);
		}
		else {
			reqHandler->pollSocketForReadOrWrite(NULL, rp->_ss_ptr->impl()->sockfd(),
												Poco::evnet::EVLHTTPRequestHandler::READ, rp->_timeout);
		}
		return lua_yieldk(L, 0, (lua_KContext)rp, recv_data_from_socket_complete);
	}
	else {
		free(rp);
		lua_pushinteger(L, ret);
		return 1;
	}
}

static int recv_data_from_socket_initiate(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	void * buf = lua_touserdata(L, 2);
	if (!buf) {
		return luaL_error(L, "recv_data_from_socket: invalid second argumet");
	}
	size_t size = luaL_checkinteger(L, 3);
	memset(buf, 0, size);

	int timeout = -1;
	if (lua_gettop(L) > 3) {
		timeout = luaL_checkinteger(L, 4);
	}

	int wait_mode = 0;
	//DEBUGPOINT("Here ss_ptr->fd = [%d]\n", ss_ptr->impl()->sockfd());
	long ret = EVTCPServer::receiveData(*(ss_ptr), buf, size, &wait_mode);
	if (ret < 0) {
		DEBUGPOINT("Here fd=[%d] ret=[%ld] {%d:%s}\n", ss_ptr->impl()->sockfd(), ret, errno, strerror(errno));
		return luaL_error(L, "recv_data_from_socket: Failed to receive data from socket: %s", strerror(errno));
	}
	else if (ret == 0) {
		struct _read_s* rp = (struct _read_s*)malloc(sizeof(struct _read_s));
		memset(rp, 0, sizeof(struct _read_s));
		rp->_buf = buf;
		rp->_size = size;
		rp->_ss_ptr = ss_ptr;
		rp->_timeout = timeout;
		if (wait_mode == -2) {
			reqHandler->pollSocketForReadOrWrite(NULL, rp->_ss_ptr->impl()->sockfd(),
											Poco::evnet::EVLHTTPRequestHandler::WRITE, rp->_timeout);
		}
		else {
			reqHandler->pollSocketForReadOrWrite(NULL, rp->_ss_ptr->impl()->sockfd(),
											Poco::evnet::EVLHTTPRequestHandler::READ, rp->_timeout);
		}
		return lua_yieldk(L, 0, (lua_KContext)rp, recv_data_from_socket_complete);
	}
	else {
		//DEBUGPOINT("Here %ld\n", ret);
		lua_pushinteger(L, ret);
		return 1;
	}
}

static int ev_hibernation_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();

	return 0;
}

static int ev_dbg_pthread_self(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	//DEBUGPOINT("Here for sock =[%d]\n", reqHandler->getAcceptedSocket()->getSockfd());
	const char * str = "";
	if (lua_gettop(L) > 0) {
		const char * str = luaL_checkstring(L, 1);
		DEBUGPOINT(" [%s]\n", str);
	}
	else {
		DEBUGPOINT("\n");
	}
	return 0;
}

static int get_sock_fd(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	//DEBUGPOINT("Here for sock =[%d]\n", reqHandler->getAcceptedSocket()->getSockfd());
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);

	lua_pushinteger(L, ss_ptr->impl()->sockfd());

	return 1;
}

static int ev_hibernation_initiate(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int time_in_s = (int)luaL_checkinteger(L, 1);

	reqHandler->evTimer(time_in_s);

	return lua_yieldk(L, 0, (lua_KContext)0, ev_hibernation_complete);
}

static int track_ss_as_websocket_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();

	return 0;
}

static int track_ss_as_websocket(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	const char * msg_handler = NULL;
	if (!lua_isnil(L, 2)) {
		if (!lua_isstring(L, 2)) {
			luaL_error(L, "track_ss_as_websocket: 2nd arument should be nil or string");
			return 0;
		}
		msg_handler = (const char *)lua_tostring(L, 2);
	}

	reqHandler->trackAsWebSocket(*ss_ptr, msg_handler);

	return lua_yieldk(L, 0, (lua_KContext)0, track_ss_as_websocket_complete);
}

static int shutdown_websocket(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	int type = 3;

	if (lua_gettop(L) > 1) {
		type = luaL_checkinteger(L, 2);
	}

	//DEBUGPOINT("ptr = [%p] sock = [%d]\n", ss_ptr, ss_ptr->impl()->sockfd());
	reqHandler->shutdownWebSocket(*ss_ptr, type);

	return 0;
}

static int async_run_lua_script_complete(lua_State* L, int status, lua_KContext ctx)
{
	int argc = lua_gettop(L);
	char ** argv = (char**)ctx;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	bool ret = true;
	if (usN.getRet() != 0) ret = false;

	lua_pushboolean(L, ret);

	/*
	for (int i = 0; i < argc; i++) {
		free(argv[i]);
	}
	*/
	free(argv);
	return 1;
}

static int async_run_lua_script_singleton(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	int argc = lua_gettop(L);
	char **argv = (char**)malloc(argc*sizeof(char*));
	for (int i = 0; i < argc; i++) {
		argv[i] = (char*)(luaL_checkstring(L, (i+1)));
	}

	reqHandler->asyncRunLuaScript(argc, argv, true);
	return lua_yieldk(L, 0, (lua_KContext)argv, async_run_lua_script_complete);
}

static int async_run_lua_script(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	int argc = lua_gettop(L);
	char **argv = (char**)malloc(argc*sizeof(char*));
	for (int i = 0; i < argc; i++) {
		argv[i] = (char*)(luaL_checkstring(L, (i+1)));
	}

	reqHandler->asyncRunLuaScript(argc, argv);
	return lua_yieldk(L, 0, (lua_KContext)argv, async_run_lua_script_complete);
}

static int websocket_active_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	bool active = (bool)usN.getRet();
	lua_pushboolean(L, active);
	return 1;
}

static int websocket_active(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);

	reqHandler->webSocketActive(*ss_ptr);
	if (ss_ptr->impl()->sockfd() == POCO_INVALID_SOCKET) {
		lua_pushboolean(L, false);
		return 1;
	}
	return lua_yieldk(L, 0, (lua_KContext)0, websocket_active_complete);
}

static int debug_ss_ptr(lua_State* L)
{
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	DEBUGPOINT("LUA STATE = [%p] Socket fd = [%d] socket_active = [%d]\n", L, ss_ptr->impl()->sockfd(), socket_live(ss_ptr->impl()->sockfd()));
	return 0;
}

static int socket_active(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);

	int active = socket_live(ss_ptr->impl()->sockfd());
	lua_pushboolean(L, active);

	return 1;

}

#include <sys/select.h>
static int old_websocket_active(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	fd_set fdRead;
	fd_set fdWrite;
	fd_set fdExcept;
	FD_ZERO(&fdRead);
	FD_ZERO(&fdWrite);
	FD_ZERO(&fdExcept);
	FD_SET(ss_ptr->impl()->sockfd(), &fdRead);
	FD_SET(ss_ptr->impl()->sockfd(), &fdWrite);
	struct timeval tv;
	tv.tv_sec  = (long) 0;
	tv.tv_usec = (long) 0;
	int rc = 0;
	//rc = select(int(ss_ptr->impl()->sockfd()) + 1, &fdRead, &fdWrite, &fdExcept, &tv);
START_LABEL:
	rc = select(int(ss_ptr->impl()->sockfd()) + 1, &fdRead, &fdWrite, &fdExcept, &tv);
	if (rc == -1) {
		lua_pushboolean(L, false);
	}
	else if (rc == 0) {
		tv.tv_sec  = (long) 0;
		tv.tv_usec = (long) 100;
		DEBUGPOINT("Here\n");
		goto START_LABEL;
	}
	else {
		lua_pushboolean(L, true);
	}
	return 1;

}

static int send_data_on_acc_socket_complete(lua_State* L, int status, lua_KContext ctx)
{
	size_t size = (size_t) ctx;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	StreamSocket * ss_ptr = *(StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	bool ret = (bool)usN.getRet();

	if (!ret) {
		luaL_error(L, "Send data on [%d] failed\n", ss_ptr->impl()->sockfd());
	}

	lua_pushinteger(L, size);

	return 1;
}

static int send_data_on_acc_socket(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	void * buf = lua_touserdata(L, 2);
	if (!buf) {
		return luaL_error(L, "send_data_on_acc_socket: invalid second argumet");
	}
	size_t size = luaL_checkinteger(L, 3);
	//DEBUGPOINT("buf = [%p] size = [%zu]\n", buf, size);
	reqHandler->sendRawDataOnAccSocket(*ss_ptr, buf, size);

	//DEBUGPOINT("Here size = [%zd]\n", size);
	return lua_yieldk(L, 0, (lua_KContext)size, send_data_on_acc_socket_complete);
}

static int complete_send_data_on_socket(lua_State* L, int status, lua_KContext ctx)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	struct _write_s* wp = (struct _write_s*)ctx;
	int wait_mode = 0;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() < 0) {
		DEBUGPOINT("Here usN.getRet() = [%ld] error=[%s]\n", usN.getRet(), strerror(usN.getErrNo()));
		free(wp);
		return luaL_error(L, "send_data_on_socket: %s", strerror(usN.getErrNo()));
	}

	long ret = EVTCPServer::sendData(*(wp->_ss_ptr), ((unsigned char*)(wp->_buf)+wp->_written), (wp->_size - wp->_written), &wait_mode);
	//DEBUGPOINT("HERE wait_mode = %d\n", wait_mode);
	if (ret < 0) {
		//DEBUGPOINT("Here %ld {%d:%s} fd=%d\n", ret, errno, strerror(errno), wp->_ss_ptr->impl()->sockfd());
		free(wp);
		return luaL_error(L, "send_data_on_socket: %s", strerror(errno));
	}
	else if (ret == 0) {
		if (wait_mode == -1) {
			reqHandler->pollSocketForReadOrWrite(NULL, wp->_ss_ptr->impl()->sockfd(),
												Poco::evnet::EVLHTTPRequestHandler::READ, wp->_timeout);
		}
		else {
			reqHandler->pollSocketForReadOrWrite(NULL, wp->_ss_ptr->impl()->sockfd(),
												Poco::evnet::EVLHTTPRequestHandler::WRITE, wp->_timeout);
		}
		return lua_yieldk(L, 0, (lua_KContext)wp, complete_send_data_on_socket);
	}
	else {
		//DEBUGPOINT("Here %ld\n", ret);
		if ((ret + wp->_written) == wp->_size) {
			lua_pushinteger(L, wp->_size);
			free(wp);
			return 1;
		}
		else {
			wp->_written += ret;
			//DEBUGPOINT("Here\n");
			if (wait_mode == -1) {
				reqHandler->pollSocketForReadOrWrite(NULL, wp->_ss_ptr->impl()->sockfd(),
													Poco::evnet::EVLHTTPRequestHandler::READ, wp->_timeout);
			}
			else {
				reqHandler->pollSocketForReadOrWrite(NULL, wp->_ss_ptr->impl()->sockfd(),
													Poco::evnet::EVLHTTPRequestHandler::WRITE, wp->_timeout);
			}
			return lua_yieldk(L, 0, (lua_KContext)wp, complete_send_data_on_socket);
		}
	}
}

static int send_data_on_socket_initiate(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	void * buf = lua_touserdata(L, 2);
	if (!buf) {
		return luaL_error(L, "send_data_on_socket: invalid second argumet");
	}
	size_t size = luaL_checkinteger(L, 3);
	int timeout = -1;
	if (lua_gettop(L) > 3) {
		timeout = luaL_checkinteger(L, 4);
	}


	int wait_mode = 0;
	long ret = EVTCPServer::sendData(*(ss_ptr), buf, size, &wait_mode);
	if (ret < 0) {
		//DEBUGPOINT("Here %ld {%d:%s}\n", ret, errno, strerror(errno));
		return luaL_error(L, "send_data_on_socket: %s", strerror(errno));
	}
	else if (ret == 0) {
		struct _write_s* wp = (struct _write_s*)malloc(sizeof(struct _write_s));
		memset(wp, 0, sizeof(struct _write_s));
		wp->_buf = buf;
		wp->_size = size;
		wp->_ss_ptr = ss_ptr;
		wp->_written = 0;
		wp->_timeout = timeout;
		//DEBUGPOINT("Here\n");
		if (wait_mode == -1) {
			reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
												Poco::evnet::EVLHTTPRequestHandler::READ, wp->_timeout);
		}
		else {
			reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
												Poco::evnet::EVLHTTPRequestHandler::WRITE, wp->_timeout);
		}
		return lua_yieldk(L, 0, (lua_KContext)wp, complete_send_data_on_socket);
	}
	else {
		//DEBUGPOINT("Here %ld\n", ret);
		if (ret == size) {
			//DEBUGPOINT("Here [%ld]\n", size);
			lua_pushinteger(L, size);
			return 1;
		}
		else {
			struct _write_s* wp = (struct _write_s*)malloc(sizeof(struct _write_s));
			memset(wp, 0, sizeof(struct _write_s));
			wp->_buf = buf;
			wp->_ss_ptr = ss_ptr;
			wp->_written = ret;
			wp->_timeout = timeout;
			//DEBUGPOINT("Here\n");
			if (wait_mode == -1) {
				reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
													Poco::evnet::EVLHTTPRequestHandler::READ, wp->_timeout);
			}
			else {
				reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
													Poco::evnet::EVLHTTPRequestHandler::WRITE, wp->_timeout);
			}
			return lua_yieldk(L, 0, (lua_KContext)wp, complete_send_data_on_socket);
		}
	}
}

static int complete_send_cms_on_socket(lua_State* L, int status, lua_KContext ctx)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	struct _write_s* wp = (struct _write_s*)ctx;
	Poco::Net::StreamSocket * ss_ptr = wp->_ss_ptr;

	if (usN.getRet() < 0) {
		DEBUGPOINT("Here usN.getRet() = [%ld] error=[%s]\n", usN.getRet(), strerror(usN.getErrNo()));
		free(wp);
		return luaL_error(L, "send_cms_on_socket: failed: %s", strerror(usN.getErrNo()));
	}

	chunked_memory_stream * cms = (chunked_memory_stream *)wp->_buf;
	{
		void * nodeptr = 0;
		void * buffer = 0;
		size_t bytes = 0;
		size_t total_bytes = wp->_written;
		int wait_mode = 0;
		long ret = 0;

		nodeptr = cms->get_next(0);
		while (nodeptr) {

			wait_mode = 0;
			ret = 0;

			buffer = cms->get_buffer(nodeptr);
			bytes = cms->get_buffer_len(nodeptr);

			ret = EVTCPServer::sendData(*(ss_ptr), buffer, bytes, &wait_mode);
			if (ret < 0) {
				free(wp);
				return luaL_error(L, "send_cms_on_socket: failed: %s", strerror(errno));
			}
			else if (ret == 0) {
				wp->_written = total_bytes;
				if (wait_mode == -1) {
					reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
														Poco::evnet::EVLHTTPRequestHandler::READ, wp->_timeout);
				}
				else {
					reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
														Poco::evnet::EVLHTTPRequestHandler::WRITE, wp->_timeout);
				}
				return lua_yieldk(L, 0, (lua_KContext)wp, complete_send_cms_on_socket);
			}
			else {
				cms->erase(ret);
				nodeptr = cms->get_next(0);
				buffer = 0;
				bytes = 0;
				total_bytes += ret;
				ret = 0;
			}
		}

		free(wp);
		lua_pushinteger(L,  total_bytes);
		return 1;
	}
}

static int send_cms_on_socket_initiate(lua_State* L)
{
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	void * ptr = lua_touserdata(L, 2);
	int timeout = -1;
	if (lua_gettop(L) > 2) {
		timeout = luaL_checkinteger(L, 3);
	}

	chunked_memory_stream * cms = *(chunked_memory_stream**)ptr;
	if (!cms) {
		return luaL_error(L, "send_cms_on_socket: invalid second argumet");
	}
	{
		void * nodeptr = 0;
		void * buffer = 0;
		size_t bytes = 0;
		size_t total_bytes = 0;
		int wait_mode = 0;
		long ret = 0;

		nodeptr = cms->get_next(0);
		while (nodeptr) {

			wait_mode = 0;
			ret = 0;

			buffer = cms->get_buffer(nodeptr);
			bytes = cms->get_buffer_len(nodeptr);

			ret = EVTCPServer::sendData(*(ss_ptr), buffer, bytes, &wait_mode);
			if (ret < 0) {
				return luaL_error(L, "send_cms_on_socket: %s", strerror(errno));
			}
			else if (ret == 0) {
				struct _write_s* wp = (struct _write_s*)malloc(sizeof(struct _write_s));
				memset(wp, 0, sizeof(struct _write_s));
				wp->_buf = (void*)cms;
				wp->_ss_ptr = ss_ptr;
				wp->_written = total_bytes;
				wp->_timeout = timeout;
				if (wait_mode == -1) {
					reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
														Poco::evnet::EVLHTTPRequestHandler::READ, wp->_timeout);
				}
				else {
					reqHandler->pollSocketForReadOrWrite(NULL, ss_ptr->impl()->sockfd(),
														Poco::evnet::EVLHTTPRequestHandler::WRITE, wp->_timeout);
				}
				return lua_yieldk(L, 0, (lua_KContext)wp, complete_send_cms_on_socket);
			}
			else {
				cms->erase(ret);
				nodeptr = cms->get_next(0);
				buffer = 0;
				bytes = 0;
				total_bytes += ret;
				ret = 0;
			}
		}

		lua_pushinteger(L,  total_bytes);
		return 1;
	}
}

static int nb_make_http_connection_complete(lua_State* L, long task_id, evl_async_task* tp)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	EVHTTPClientSession *session = tp->_session_ptr;
	Poco::evnet::EVEventNotification *usN_ptr = tp->_usN;

	tp->_session_ptr = NULL;
	tp->_usN = NULL;
	if (usN_ptr->getRet() < 0) {
		if (usN_ptr->getConnSock()) delete usN_ptr->getConnSock();
		delete session;
		delete usN_ptr;
		char msg[1024];
		sprintf(msg, "make_http_connection: could not establish connection: %s", strerror(usN_ptr->getErrNo()));
		lua_pushnil(L);
		lua_pushstring(L, msg);
		lua_pushnil(L);
		luaL_error(L, msg);

		return 3;
	}
	if ((usN_ptr->getRet() < 0) || usN_ptr->getErrNo()) {
		if (usN_ptr->getConnSock()) delete usN_ptr->getConnSock();
		delete session;
		char msg[1024];
		sprintf(msg, "make_http_connection: could not establish connection: %s", strerror(usN_ptr->getErrNo()));
		lua_pushnil(L);
		lua_pushstring(L, msg);
		lua_pushnil(L);
		luaL_error(L, msg);

		return 3;
	}

	void * ptr = lua_newuserdata(L, sizeof(EVHTTPClientSession *)); //Stack: ptr
	*(EVHTTPClientSession **)ptr = session; //Stack: session
	luaL_setmetatable(L, _http_conn_type_name); // Stack: session
	lua_pushnil(L); // Stack session nil
	{
		Poco::Net::StreamSocket * ss_ptr = new StreamSocket(session->getSS());
		//*(ss_ptr) = session->getSS();
		void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
		*(Poco::Net::StreamSocket**)ptr = ss_ptr;
		luaL_setmetatable(L, _stream_socket_type_name);
	}
	{
		EVConnectedStreamSocket* cn = usN_ptr->getConnSock();
		session->setConnSock(usN_ptr->getConnSock());
		void * ptr = lua_newuserdata(L, sizeof(EVConnectedStreamSocket*));
		*(void**)ptr = (void*)cn;
		luaL_setmetatable(L, _ev_connected_socket_type_name);
	}

	delete usN_ptr;
	reqHandler->getAsyncTaskList().erase(task_id);
	return 4;
}

static int task_return_value(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	int n = lua_gettop(L);
	if (n != 1) {
		luaL_error(L, "wait: Invalid number of parameters %d, expected 1", n);
		return 0;
	}

	long task_id = luaL_checkinteger(L, 1);

	evl_async_task* tp = reqHandler->get_async_task(task_id);
	if (!tp) {
		char str[1024] = {0};
		lua_pushnil(L);
		sprintf(str, "No such task [%ld]",task_id);
		lua_pushstring(L, str);
		return 2;
	}

	if (tp->_task_tracking_state != evl_async_task::COMPLETE) {
		char str[1024] = {0};
		lua_pushnil(L);
		sprintf(str, "Task [%ld] is not tracked to completion",task_id);
		lua_pushstring(L, str);
		return 2;
	}

	switch (tp->_task_action) {
		case evl_async_task::MAKE_HTTP_CONNECTION:
			{
				return nb_make_http_connection_complete(L, task_id, tp);
			}
			break;
		case evl_async_task::RECV_HTTP_RESPONSE:
			{
				return nb_fetch_arrived_http_response(L, task_id, tp);
			}
			break;
		default:
			{
				char str[1024] = {0};
				lua_pushnil(L);
				sprintf(str, "Task type [%d] not supported", tp->_task_action);
				lua_pushstring(L, str);
				return 2;
			}
	}

	return 0;
}

static int nb_make_http_connection_initiate(lua_State* L)
{
	long sr_num;
	//DEBUGPOINT("HERE %d\n", lua_gettop(L));
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	EVHTTPClientSession *session = NULL;;
	if (lua_gettop(L) < 2) {
		luaL_error(L, "make_http_connection: invalid number of arguments, expected 2, actual %d ", lua_gettop(L));
		return 0;
	}
	else if (lua_isnil(L, 1) || !lua_isstring(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "make_http_connection: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else if (!lua_isnil(L, 2) && !lua_isstring(L, 2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
		luaL_error(L, "make_http_connection: invalid second argumet %s", lua_typename(L, lua_type(L, 2)));
		return 0;
	}
	int timeout = -1;
	if (lua_gettop(L) > 2) {
		timeout = luaL_checkinteger(L, 3);
	}
	const char * server_address = lua_tostring(L, 1);
	int value = 0; lua_numbertointeger(lua_tonumber(L, 2), &value);
	unsigned short  port_num = (unsigned short)value;

	//DEBUGPOINT("Server address = [%s], port_num = [%d] timeout = [%d]\n", server_address, value, timeout);
	session = new EVHTTPClientSession();
	//DEBUGPOINT("Server address = [%s], port_num = [%d] timeout = [%d]\n", server_address, value, timeout);
	sr_num = reqHandler->makeNewHTTPConnection(NULL, server_address, port_num, *session, timeout);
	reqHandler->track_async_task(sr_num, evl_async_task::MAKE_HTTP_CONNECTION, session);

	lua_pushinteger(L, sr_num);

	return 1;
}

static int old_close_http_connection(lua_State* L)
{
	int value = 0;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	EVHTTPClientSession * session = *(EVHTTPClientSession **)luaL_checkudata(L, 1, _http_conn_type_name);
	//reqHandler->closeHTTPSession(*session);
	session->setState(EVHTTPClientSession::CLOSED);
	//session->getConnSock()->cleanupSocket();
	int fd = session->getSS().impl()->sockfd();
	DEBUGPOINT("Here fd = [%d]\n", fd);
	/*
	*/
	//session->getSS().impl()->shutdownSend();
	//session->getSS().impl()->shutdownReceive();
	session->getSS().impl()->close();

	int ret = 1;
	char * chptr[1024];
	while (ret > 0) {
		ret = recv(fd, chptr, 1024 , 0);
		DEBUGPOINT("ret = [%d] fd = [%d] error=[%s]\n", ret, fd, strerror(errno));
	}


	return 0;
}

static int close_http_connection_finalize(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	EVHTTPClientSession * session = (EVHTTPClientSession *)ctx;
	//DEBUGPOINT("here\n");

	return 0;
}

static int close_http_connection(lua_State* L)
{
	int value = 0;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	EVHTTPClientSession * session = *(EVHTTPClientSession **)luaL_checkudata(L, 1, _http_conn_type_name);
	reqHandler->closeHTTPSession(*session);

	//DEBUGPOINT("BEFORE YIELD LUA_STATE[%p]\n", L);
	return lua_yieldk(L, 0, (lua_KContext)session, close_http_connection_finalize);
}

static int req__gc(lua_State *L)
{
	Poco::Net::HTTPRequest* request = *(Poco::Net::HTTPRequest**)lua_touserdata(L, 1);
	delete request;
	return 0;
}

static int new_request(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	EVHTTPRequest* request = new EVHTTPRequest();

	void * ptr = lua_newuserdata(L, sizeof(EVHTTPRequest*));
	*(EVHTTPRequest**)ptr = request;
	luaL_setmetatable(L, _http_creq_type_name);

	return 1;
}

// This is request header send
static int send_request_header(lua_State* L)
{
	//DEBUGPOINT("Here\n");
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
	//DEBUGPOINT("Here\n");
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

static int nb_fetch_arrived_http_response(lua_State* L, long task_id, evl_async_task* tp)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	EVHTTPResponse* response = tp->_response_ptr;
	Poco::evnet::EVEventNotification *usN_ptr = tp->_usN;

	tp->_response_ptr = NULL;
	tp->_usN = NULL;
	if (usN_ptr->getRet() < 0) {
		delete response;
		delete usN_ptr;
		char msg[1024];
		sprintf(msg, "receive_http_response: could not receieve response: %s", strerror(usN_ptr->getErrNo()));
		lua_pushnil(L);
		lua_pushstring(L, msg);
		return 2;
	}

	void * ptr = lua_newuserdata(L, sizeof(EVHTTPResponse*));
	*(EVHTTPResponse**)ptr = response;
	luaL_setmetatable(L, _http_cresp_type_name);
	lua_pushnil(L); // Stack response nil

	delete usN_ptr;
	reqHandler->getAsyncTaskList().erase(task_id);

	return 2;
}

static int nb_subscribe_to_http_response(lua_State* L)
{
	long sr_num = -1;;
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "nb_subscribe_to_http_response: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	int timeout = -1;
	if (lua_gettop(L) > 1) {
		timeout = luaL_checkinteger(L, 2);
	}
	EVHTTPClientSession& session = *(*(EVHTTPClientSession**)lua_touserdata(L, 1));
	EVHTTPResponse* response = new EVHTTPResponse();

	sr_num = reqHandler->waitForHTTPResponse(NULL, (session), *response, timeout);
	reqHandler->track_async_task(sr_num, evl_async_task::RECV_HTTP_RESPONSE, response);

	lua_pushinteger(L, sr_num);

	return 1;

}

static int receive_http_response_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	EVHTTPResponse* response = (EVHTTPResponse*)ctx;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() < 0) {
		delete response;
		char msg[1024];
		luaL_error(L, msg, "receive_http_response: error: %s", strerror(usN.getErrNo()));
		return 1;
	}

	void * ptr = lua_newuserdata(L, sizeof(EVHTTPResponse*));
	*(EVHTTPResponse**)ptr = response;
	luaL_setmetatable(L, _http_cresp_type_name);

	return 1;
}

static int receive_http_response_initiate(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "send_request_header: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	int timeout = -1;
	if (lua_gettop(L) > 1) {
		timeout = luaL_checkinteger(L, 2);
	}
	EVHTTPClientSession& session = *(*(EVHTTPClientSession**)lua_touserdata(L, 1));
	EVHTTPResponse* response = new EVHTTPResponse();

	reqHandler->waitForHTTPResponse(NULL, (session), *response, timeout);
	return lua_yieldk(L, 0, (lua_KContext)response, receive_http_response_complete);
}

static int ev_lua_file_open_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::file_handle_p fh = (Poco::evnet::file_handle_p)ctx;
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() < 0) {
		DEBUGPOINT("fh = %p, fd = %d\n", fh, fh->get_fd());
		char str[1024] = {0};
		sprintf(str, "file_open: file could not be opened: %s", strerror(usN.getErrNo()));
		lua_pushnil(L);
		lua_pushstring(L, str);
		reqHandler->ev_file_close(fh);
		return 2;
	}

	//DEBUGPOINT("Opening file id %d\n", fh->get_fd());

	void * ptr = lua_newuserdata(L, sizeof(Poco::evnet::file_handle_p));
	*(Poco::evnet::file_handle_p*)ptr = fh;
	luaL_setmetatable(L, _file_handle_type_name);

	return 1;
}

static int ev_lua_file_open_initiate(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);
	if (n != 2) {
		return luaL_error(L, "file_open: invalid number of arguments, expetcted 2, actual %d", lua_gettop(L));
	}
	if (!lua_isstring(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		return luaL_error(L, "file_open: invalid first argumet type %s", lua_typename(L, lua_type(L, 1)));
	}
	if (!lua_isstring(L, 2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
		return luaL_error(L, "file_open: invalid second argumet type %s", lua_typename(L, lua_type(L, 2)));
	}

	const char * file_name = NULL;
	const char * permission = NULL;

	if (strchr(lua_tostring(L, 1), ' ') || strchr(lua_tostring(L, 1), '\t') || strchr(lua_tostring(L, 1), '\n')) {
		DEBUGPOINT("Here %s\n", lua_tostring(L, 1));
		return luaL_error(L, "file_open: invald first argument, white space not allowed  %s", lua_tostring(L, 1));
	}
	file_name = lua_tostring(L, 1);
	if (strcmp("r", lua_tostring(L, 2)) && strcmp("w", lua_tostring(L, 2)) && strcmp("a", lua_tostring(L, 2)) &&
		strcmp("r+", lua_tostring(L, 2)) && strcmp("w+", lua_tostring(L, 2)) && strcmp("a+", lua_tostring(L, 2))) {
		DEBUGPOINT("Here %s\n", lua_tostring(L, 2));
		return luaL_error(L, "file_open: invald second argument %s, allowed: r, w, a, r+, w+, a+", lua_tostring(L, 2));
	}
	permission = lua_tostring(L, 2);
	int oflag = 0;
	if (permission[1] == '+') {
		switch (permission[0]) {
			case 'r':
				oflag |= O_RDWR;
				break;
			case 'w':
				oflag |= O_RDWR|O_TRUNC|O_CREAT;
				break;
			case 'a':
				oflag |= O_RDWR|O_APPEND|O_CREAT;
				break;
			default:
				return luaL_error(L, "file_open: invald second argument %s, allowed: r, w, a, r+, w+, a+", lua_tostring(L, 2));
		}
	}
	else {
		switch (permission[0]) {
			case 'r':
				oflag |= O_RDONLY;
				break;
			case 'w':
				oflag |= O_WRONLY|O_CREAT;
				break;
			case 'a':
				oflag |= O_RDWR|O_CREAT;
				break;
			default:
				return luaL_error(L, "file_open: invald second argument %s, allowed: r, w, a, r+, w+, a+", lua_tostring(L, 2));
		}
	}

	Poco::evnet::file_handle_p fh = NULL;
	if (oflag&O_CREAT) {
		fh = reqHandler->ev_file_open(file_name, oflag, 0644);
	}
	else {
		fh = reqHandler->ev_file_open(file_name, oflag);
	}

	if (fh == NULL) {
		DEBUGPOINT("OPEN CALL FAILED %s\n", strerror(errno));
		char str[1024] = {0};
		sprintf(str, "file_open: open call failed: %s", strerror(errno));
		lua_pushnil(L);
		lua_pushstring(L, str);
		return 2;
	}

	reqHandler->pollFileOpenStatus(NULL, fh->get_fd());
	return lua_yieldk(L, 0, (lua_KContext)fh, ev_lua_file_open_complete);
}

static void validate_file_handle(lua_State* L)
{
	if (!lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "file_close: invalid argumet type: %s", lua_typename(L, lua_type(L, 1)));
		return;
	}

	Poco::evnet::file_handle_p fh = NULL;
	void * ptr = luaL_checkudata(L, 1, _file_handle_type_name);
	fh = *(Poco::evnet::file_handle_p*)ptr;
	if (!fh) {
		luaL_error(L, "Invaid file handle ");
		return;
	}

	return ;
}

static int ev_lua_file_read_text_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	struct _read_s* rp = (struct _read_s*)ctx;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();

	ssize_t nbyte = usN.getRet();
	errno = usN.getErrNo();
	//DEBUGPOINT("Here fd = %d complete nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte < 0) {
		char str[1024] = {0};
		sprintf(str, "read_text: file read failed: %s", strerror(errno));
		lua_pushnil(L);
		lua_pushstring(L, str);
		reqHandler->ev_file_close(rp->_fh);
		free(rp->_buf);
		free(rp);
		return 2;
	}
	else if (nbyte == 0) {
		char str[1024] = {0};
		sprintf(str, "read_text: EOF reached");
		lua_pushnil(L);
		lua_pushstring(L, str);
		free(rp->_buf);
		free(rp);
		return 2;
	}

	memset(rp->_buf, 0, rp->_size+1);
	nbyte = reqHandler->ev_file_read(rp->_fh, rp->_buf, rp->_size);
	//DEBUGPOINT("Here fd = %d complete nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte > 0) {
		lua_pushstring(L, (const char*)rp->_buf);
		lua_pushstring(L, NULL);
		free(rp->_buf);
		free(rp);
		return 2;
	}
	else {
		if (errno == EAGAIN) {
			return ev_lua_file_read_text_initiate(L);
		}
		free(rp->_buf);
		free(rp);
		return luaL_error(L, "file_read_text: failed for unknown reason");
	}
}

/* local string = fh.read_text(fh, size); */
static int ev_lua_file_read_text_initiate(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);
	if (n != 2) {
		return luaL_error(L, "read_text: invalid number of arguments, expetcted 2, actual %d", lua_gettop(L));
	}

	struct _read_s* rp = (struct _read_s*)malloc(sizeof(struct _read_s));
	memset(rp, 0, sizeof(struct _read_s));

	rp->_timeout = 0;
	rp->_fh = *(Poco::evnet::file_handle_p*)luaL_checkudata(L, 1, _file_handle_type_name);
	rp->_size = luaL_checkinteger(L, 2);
	if (rp->_size <= 0) {
		return luaL_error(L, "read_text: size must be greater than 0");
	}

	rp->_buf = malloc(rp->_size+1);
	memset(rp->_buf, 0, rp->_size+1);

	ssize_t nbyte = reqHandler->ev_file_read(rp->_fh, rp->_buf, rp->_size);
	//DEBUGPOINT("Here fd = %d initiate nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte < 0 && errno != EAGAIN) {
		char str[1024] = {0};
		sprintf(str, "read_text: file read failed: %s", strerror(errno));
		lua_pushnil(L);
		lua_pushstring(L, str);
		free(rp->_buf);
		free(rp);
		return 2;
	}
	else if (nbyte == 0) {
		char str[1024] = {0};
		sprintf(str, "read_text: EOF reached");
		lua_pushnil(L);
		lua_pushstring(L, str);
		free(rp->_buf);
		free(rp);
		return 2;
	}
	else if (nbyte > 0) {
		lua_pushstring(L, (const char*)rp->_buf);
		lua_pushstring(L, NULL);
		free(rp->_buf);
		free(rp);
		return 2;
	}

	reqHandler->pollFileReadStatus(NULL, rp->_fh->get_fd());
	return lua_yieldk(L, 0, (lua_KContext)rp, ev_lua_file_read_text_complete);
}

static int ev_lua_file_read_binary_complete(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	struct _read_s* rp = (struct _read_s*)ctx;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();

	ssize_t nbyte = usN.getRet();
	errno = usN.getErrNo();
	//DEBUGPOINT("Here fd = %d complete nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte < 0) {
		char str[1024] = {0};
		sprintf(str, "read_binary: file read failed: %s", strerror(errno));
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		reqHandler->ev_file_close(rp->_fh);
		free(rp);
		return 2;
	}
	else if (nbyte == 0) {
		char str[1024] = {0};
		sprintf(str, "read_binary: EOF reached");
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		free(rp);
		return 2;
	}

	memset(rp->_buf, 0, rp->_size);
	nbyte = reqHandler->ev_file_read(rp->_fh, rp->_buf, rp->_size);
	//DEBUGPOINT("Here fd = %d complete nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte > 0) {
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, NULL);
		free(rp);
		return 2;
	}
	else {
		if (errno == EAGAIN) {
			return ev_lua_file_read_binary_initiate(L);
		}
		free(rp);
		DEBUGPOINT("file_read_binary: failed for unknown reason [nbyte=%zd][errno=%d][%s]\n",nbyte, errno, strerror(errno));
		return luaL_error(L, "file_read_binary: failed for unknown reason");
	}
}

/* local integer = fh.read_binary(fh, buffer, size); */
static int ev_lua_file_read_binary_initiate(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);
	if (n != 3) {
		return luaL_error(L, "read_binary: invalid number of arguments, expetcted 3, actual %d", lua_gettop(L));
	}

	struct _read_s* rp = (struct _read_s*)malloc(sizeof(struct _read_s));
	memset(rp, 0, sizeof(struct _read_s));

	rp->_timeout = 0;
	rp->_fh = *(Poco::evnet::file_handle_p*)luaL_checkudata(L, 1, _file_handle_type_name);
	rp->_buf = (Poco::evnet::file_handle_p)luaL_checkudata(L, 2, _memory_buffer_name);
	rp->_size = luaL_checkinteger(L, 3);
	if (rp->_size <= 0) {
		return luaL_error(L, "read_binary: size must be greater than 0");
	}

	ssize_t nbyte = reqHandler->ev_file_read(rp->_fh, rp->_buf, rp->_size);
	//DEBUGPOINT("Here fd = %d initiate nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte < 0 && errno != EAGAIN) {
		char str[1024] = {0};
		sprintf(str, "read_binary: file read failed: %s", strerror(errno));
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		free(rp);
		return 2;
	}
	else if (nbyte == 0) {
		char str[1024] = {0};
		sprintf(str, "read_binary: EOF reached");
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		free(rp);
		return 2;
	}
	else if (nbyte > 0) {
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, NULL);
		free(rp);
		return 2;
	}

	reqHandler->pollFileReadStatus(NULL, rp->_fh->get_fd());
	return lua_yieldk(L, 0, (lua_KContext)rp, ev_lua_file_read_binary_complete);
}

static int ev_lua_file_read_binary_complete_1(lua_State* L, int status, lua_KContext ctx)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	struct _read_s* rp = (struct _read_s*)ctx;

	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();

	ssize_t nbyte = usN.getRet();
	errno = usN.getErrNo();
	//DEBUGPOINT("Here fd = %d complete nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte < 0) {
		char str[1024] = {0};
		sprintf(str, "read_binary: file read failed: %s", strerror(errno));
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		reqHandler->ev_file_close(rp->_fh);
		free(rp);
		return 2;
	}
	else if (nbyte == 0) {
		char str[1024] = {0};
		sprintf(str, "read_binary: EOF reached");
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		free(rp);
		return 2;
	}

	memset(rp->_buf, 0, rp->_size);
	nbyte = reqHandler->ev_file_read(rp->_fh, rp->_buf, rp->_size);
	//DEBUGPOINT("Here fd = %d complete nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte > 0) {
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, NULL);
		free(rp);
		return 2;
	}
	else {
		if (errno == EAGAIN) {
			return ev_lua_file_read_binary_initiate_1(L);
		}
		free(rp);
		DEBUGPOINT("file_read_binary: failed for unknown reason [nbyte=%zd][errno=%d][%s]\n",nbyte, errno, strerror(errno));
		return luaL_error(L, "file_read_binary: failed for unknown reason");
	}
}

/* local integer = fh.read_binary(fh, buffer, size); */
static int ev_lua_file_read_binary_initiate_1(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);
	if (n != 3) {
		return luaL_error(L, "read_binary: invalid number of arguments, expetcted 3, actual %d", lua_gettop(L));
	}

	struct _read_s* rp = (struct _read_s*)malloc(sizeof(struct _read_s));
	memset(rp, 0, sizeof(struct _read_s));

	rp->_timeout = 0;
	rp->_fh = *(Poco::evnet::file_handle_p*)luaL_checkudata(L, 1, _file_handle_type_name);
	rp->_buf = (void*)lua_touserdata(L, 2);
	rp->_size = luaL_checkinteger(L, 3);
	if (rp->_size <= 0) {
		return luaL_error(L, "read_binary: size must be greater than 0");
	}

	ssize_t nbyte = reqHandler->ev_file_read(rp->_fh, rp->_buf, rp->_size);
	//DEBUGPOINT("Here fd = %d initiate nbyte = %zd , errno = %d\n", rp->_fh->get_fd(), nbyte, errno);
	if (nbyte < 0 && errno != EAGAIN) {
		char str[1024] = {0};
		sprintf(str, "read_binary: file read failed: %s", strerror(errno));
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		free(rp);
		return 2;
	}
	else if (nbyte == 0) {
		char str[1024] = {0};
		sprintf(str, "read_binary: EOF reached");
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, str);
		free(rp);
		return 2;
	}
	else if (nbyte > 0) {
		lua_pushinteger(L, nbyte);
		lua_pushstring(L, NULL);
		free(rp);
		return 2;
	}

	reqHandler->pollFileReadStatus(NULL, rp->_fh->get_fd());
	return lua_yieldk(L, 0, (lua_KContext)rp, ev_lua_file_read_binary_complete_1);
}

/* local ret = fh.write_text(fh, text); */
static int ev_lua_file_write_text(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	int n = lua_gettop(L);
	if (n != 2) {
		return luaL_error(L, "write_text: invalid number of arguments, expetcted 2, actual %d", lua_gettop(L));
	}

	Poco::evnet::file_handle_p fh = *(Poco::evnet::file_handle_p*)luaL_checkudata(L, 1, _file_handle_type_name);
	const char * text = (const char *)luaL_checkstring(L, 2);
	size_t ret = reqHandler->ev_file_write(fh, (void*)text, strlen(text));

	lua_pushinteger(L, ret);

	return 1;
}

/* local ret = fh.write_binary(fh, buffer, size); */
static int ev_lua_file_write_binary(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	int n = lua_gettop(L);
	if (n != 3) {
		return luaL_error(L, "write_text: invalid number of arguments, expetcted 3, actual %d", lua_gettop(L));
	}

	Poco::evnet::file_handle_p fh = *(Poco::evnet::file_handle_p*)luaL_checkudata(L, 1, _file_handle_type_name);
	if (lua_isnil(L, 2) || !lua_isuserdata(L, 2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
		luaL_error(L, "file:write_binary invalid second argumet %s", lua_typename(L, lua_type(L, 2)));
		lua_pushnil(L);
	}
	void * buffer = lua_touserdata(L, 2);
	size_t size = luaL_checkinteger(L, 3);

	//DEBUGPOINT("Here fd = %d\n", fh->get_fd());
	//DEBUGPOINT("Here buffer = %p\n", buffer);
	//DEBUGPOINT("%zu +\n", size);

	size_t ret = reqHandler->ev_file_write(fh, buffer, size);

	lua_pushinteger(L, ret);

	return 1;
}

static int ev_lua_file_close(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);
	if (n != 1) {
		return luaL_error(L, "file_close: invalid number of arguments, expetcted 1, actual %d", lua_gettop(L));
	}
	validate_file_handle(L);
	Poco::evnet::file_handle_p fh = NULL;

	fh = *(Poco::evnet::file_handle_p*)lua_touserdata(L, 1);
	reqHandler->ev_file_close(fh);

	return 0;
}

static int alloc_buffer(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	int n = lua_gettop(L);

	if (n != 1) {
		return luaL_error(L, "alloc_buffer: invalid number of arguments, expetcted 1, actual %d", lua_gettop(L));
	}

	if (!lua_isinteger(L, 1)) {
		return luaL_error(L, "alloc_buffer: invalid argument type %s", lua_typename(L, lua_type(L, 1)));
	}

	if (0 >= lua_tointeger(L, 1)) {
		return luaL_error(L, "alloc_buffer: invalid argument type %d, should be a positive number", lua_tointeger(L, 1));
	}

	size_t alloc_size = lua_tointeger(L, 1);

	lua_getglobal(L, S_CURRENT_ALLOC_SIZE);
	size_t current_allocation = lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getglobal(L, S_MAX_MEMORY_ALLOC_LIMIT);
	size_t max_allocation_limit = lua_tointeger(L, -1);
	lua_pop(L, 1);

	if ((current_allocation + alloc_size) > max_allocation_limit) {
		char str[1024] = {0};
		sprintf(str,
			"alloc_buffer: unable to allocate %zd bytes, exceeds memory limit [%zd] \n",
			alloc_size, max_allocation_limit);
		return luaL_error(L, str);
	}

	void * ptr = lua_newuserdata(L, alloc_size);
	luaL_setmetatable(L, _memory_buffer_name);

	current_allocation += alloc_size;
	lua_pushinteger(L, current_allocation);
	lua_setglobal(L, S_CURRENT_ALLOC_SIZE);

	return 1;
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
		const bool value = lua_toboolean(L, -1);
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
		//DEBUGPOINT("%s:%d [%s][%s]\n", __FILE__, __LINE__, name, value);
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
				DEBUGPOINT("EXCEPTION: %s\n",ex.what());
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
		PartData * pd = NULL;
		auto it = parts.find(s);
		if (parts.end() != it)
			pd = parts[s];

		if (!pd) {
			lua_pushnil(L);
			return 1;
		}

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
			luaL_error(L, "EXCEPTION: %s", ex.what());
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
	int n = lua_gettop(L);
	EVHTTPRequest& request = *(*(EVHTTPRequest**)luaL_checkudata(L, 1, _http_creq_type_name));
	std::ostream& ostr = *(request.getRequestStream());
	if (n==2) {
		ostr << luaL_checkstring(L, 2);
		ostr << std::flush;
	}
	else if (n== 3) {
		if (lua_isnil(L, 2) || !lua_isuserdata(L, 2)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
			luaL_error(L, "request:write invalid first argumet %s", lua_typename(L, lua_type(L, 2)));
			lua_pushnil(L);
		}
		void * buf = lua_touserdata(L, 2);
		int size = luaL_checkinteger(L, 3);
		ostr.write((const char *)buf, size);
		ostr << std::flush;
	}
	else {
		return luaL_error(L, "ostream:write: invalid number of argumets %d", n);
	}

	return 0;
}

static int read_buff(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "request:read_buff: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else {
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, 1));
		std::istream& istr = request.stream();
		memset(reqHandler->getEphemeralBuf(), 0, EVL_EPH_BUFFER_SIZE);
		istr.read(reqHandler->getEphemeralBuf(), EVL_EPH_BUFFER_SIZE);
		size_t size = istr.gcount();
		if (size) {
			lua_pushlightuserdata(L, reqHandler->getEphemeralBuf());
			lua_pushinteger(L, size);
		}
		else {
			lua_pushnil(L);
		}
	}
	return 1;
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

static int get_message_body_str(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "istream:get_message_body_str: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else {
		char * str_buf = (char*)reqHandler->getFromComponents(EVLHTTPRequestHandler::string_body);
		if (str_buf) {
			lua_pushstring(L, str_buf);
		}
		else {
			EVHTTPServerRequestImpl& request = *(*(EVHTTPServerRequestImpl**)lua_touserdata(L, 1));
			size_t body_size = request.getMessageBodySize();
			if (body_size) {
				str_buf = (char*)calloc(1, body_size+1);
				std::istream& istr = request.stream();
				istr.read(str_buf, body_size);
				lua_pushstring(L, str_buf);
				reqHandler->addToComponents(EVLHTTPRequestHandler::string_body, str_buf);
			}
			else {
				lua_pushnil(L);
			}
		}
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
	Net::HTTPServerRequest* requestPtr = reqHandler->getHTTPRequestPtr();
	if (requestPtr == NULL) {
		luaL_error(L, "HTTP Request not available");
	}
	Net::HTTPServerRequest& request = *requestPtr;

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

static int get_status(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	EVHTTPResponse* response = (*(EVHTTPResponse**)luaL_checkudata(L, 1, _http_cresp_type_name));
	int status = response->getStatus();

	lua_pushinteger(L, status);

	return 1;
}

static int set_status(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	Net::HTTPServerResponse* responsePtr = reqHandler->getHTTPResponsePtr();
	if (responsePtr == NULL) {
		luaL_error(L, "Response handle is not available");
	}
	Net::HTTPServerResponse& response = *responsePtr;

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
	Net::HTTPServerResponse* responsePtr = reqHandler->getHTTPResponsePtr();
	if (responsePtr == NULL) {
		luaL_error(L, "Response handle is not available");
	}
	Net::HTTPServerResponse& response = *responsePtr;

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
			luaL_error(L, "EXCEPTION: %s",  ex.what());
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
	int n = lua_gettop(L);

	Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)luaL_checkudata(L, 1, _http_sresp_type_name));
	std::ostream& ostr = response.getOStream();
	if (n==2) {
		ostr << luaL_checkstring(L, 2);
		ostr << std::flush;
	}
	else if (n== 3) {
		if (lua_isnil(L, 2) || !lua_isuserdata(L, 2)) {
			DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
			luaL_error(L, "response:write invalid second argumet %s", lua_typename(L, lua_type(L, 2)));
			lua_pushnil(L);
		}
		void * buf = lua_touserdata(L, 2);
		int size = luaL_checkinteger(L, 3);
		ostr.write((const char *)buf, size);
		ostr << std::flush;
	}
	else {
		return luaL_error(L, "ostream:write: invalid number of argumets %d", n);
	}

	return 0;
}

static int read_buff(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "response:read_buff: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else {
		EVHTTPResponse& response = *(*(EVHTTPResponse**)lua_touserdata(L, 1));
		std::istream& istr = *(response.getStream());
		memset(reqHandler->getEphemeralBuf(), 0, EVL_EPH_BUFFER_SIZE);
		istr.read(reqHandler->getEphemeralBuf(), EVL_EPH_BUFFER_SIZE);
		size_t size = istr.gcount();
		if (size) {
			lua_pushlightuserdata(L, reqHandler->getEphemeralBuf());
			lua_pushinteger(L, size);
		}
		else {
			lua_pushnil(L);
		}
	}
	return 1;
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

static int get_message_body_str(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
		luaL_error(L, "istream:get_message_body_str: invalid first argumet %s", lua_typename(L, lua_type(L, 1)));
		return 0;
	}
	else {
		EVHTTPResponse& response = *(*(EVHTTPResponse**)lua_touserdata(L, 1));
		size_t body_size = response.getMessageBodySize();
		if (body_size) {
			char * str_buf = (char*)calloc(1, body_size+1);
			std::istream& istr = *(response.getStream());
			istr.read(str_buf, body_size);
			lua_pushstring(L, str_buf);
			free(str_buf);
		}
		else {
			lua_pushnil(L);
		}
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
	luaL_newmetatable(L, _http_sreq_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_httpreq_lib); // Stack: context meta httspreq
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pushcfunction(L, http_sreq_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	//std::string meta_name = reqHandler->getDynamicMetaName();
	luaL_newmetatable(L, _http_creq_type_name); // Stack: meta
	luaL_newlib(L, evpoco_httpreq_lib); // Stack: meta httpcreq
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, evpoco::req__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, http_creq_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack: 

	//std::string meta_name = reqHandler->getDynamicMetaName();
	luaL_newmetatable(L, _stream_socket_type_name); // Stack: meta
	luaL_newlib(L, evpoco_stream_sock_lib); // Stack: meta httpcreq
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, evpoco::ss__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, stream_sock_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack: 

	//std::string meta_name = reqHandler->getDynamicMetaName();
	luaL_newmetatable(L, _ev_connected_socket_type_name); // Stack: meta
	luaL_newlib(L, evpoco_ev_conn_stream_sock_lib); // Stack: meta httpcreq
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, evpoco::ev_connected_socket_type_name__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, ev_connected_socket_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack: 

	// Stack: context
	luaL_newmetatable(L, _http_sresp_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_httpresp_lib); // Stack: context meta httpresp
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pushcfunction(L, http_sresp_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	//std::string meta_name = reqHandler->getDynamicMetaName();
	luaL_newmetatable(L, _http_cresp_type_name); // Stack: meta
	luaL_newlib(L, evpoco_httpresp_lib); // Stack: meta evpoco_httpresp_lib
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, evpoco::resp__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, http_cresp_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack:

	//std::string meta_name = reqHandler->getDynamicMetaName();
	luaL_newmetatable(L, _http_conn_type_name); // Stack: meta
	luaL_newlib(L, dummy); // Stack: meta dummy
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, evpoco::http_connection__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, http_conn_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack:

	// Stack: context
	luaL_newmetatable(L, _html_form_type_name); // Stack: context meta
	luaL_newlib(L, form_lib); // Stack: context meta form
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pushcfunction(L, html_form_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	luaL_newmetatable(L, _file_handle_type_name); // Stack: meta
	luaL_newlib(L, evpoco_file_lib); // Stack: meta dummy
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, file_handle_type_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack:

	luaL_newmetatable(L, _memory_buffer_name); // Stack: meta
	luaL_newlib(L, dummy); // Stack: meta dummy
	lua_setfield(L, -2, "__index"); // Stack: meta
	lua_pushstring(L, "__gc"); // Stack: meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: meta "__gc" fptr
	lua_settable(L, -3); // Stack: meta
	lua_pushcfunction(L, memory_buffer_name__tostring); // Stack: context meta fptr
	lua_setfield(L, -2, "__tostring"); // Stack: context meta
	lua_pop(L, 1); // Stack:

	return 1;
}

EVLHTTPRequestHandler::EVLHTTPRequestHandler():
	_L0(0),
	_L(0),
	_http_connection_count(-1),
	_variable_instance_count(0),
	_async_tasks_status_awaited(false)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	bool enable_lua_cache = config.getBool(SERVER_PREFIX_CFG_NAME + ENABLE_CACHE , true);

	*_ephemeral_buffer = 0;
	{
		if ((enable_lua_cache &&
			(_L = (lua_State*)dequeue(sg_lua_state_cache._queue)) != NULL) &&
			(lua_status(_L) == LUA_OK)) {
			//DEBUGPOINT("Found a state element\n");
			lua_settop(_L, 0);
			lua_pushlightuserdata(_L, (void*) this);
			lua_setglobal(_L, "EVLHTTPRequestHandler*");

			lua_pushinteger(_L, 0);
			lua_setglobal(_L, S_CURRENT_ALLOC_SIZE);

			return;
		}
		else {
			if (_L) {
				lua_close(_L);
			}
		}
	}
	/*
	*/
	{
		_L = luaL_newstate();
		luaL_openlibs(_L);

		lua_register(_L, "ev_sleep", evpoco::evpoco_sleep);
		//lua_register(_L, "ev_getmtname", evpoco::evpoco_getmtname);
		luaL_requiref(_L, _platform_name, &luaopen_evpoco, 1);
		/*
		 * luaL_requiref leaves a copy of the table on top of the stack.
		 * We dont require it here, so setting the top of stack back to 0.
		 */
		lua_settop(_L, 0);

		lua_pushlightuserdata(_L, (void*) this);
		lua_setglobal(_L, "EVLHTTPRequestHandler*");

		lua_pushinteger(_L, MAX_MEMORY_ALLOC_LIMIT);
		lua_setglobal(_L, S_MAX_MEMORY_ALLOC_LIMIT);

		lua_pushinteger(_L, 0);
		lua_setglobal(_L, S_CURRENT_ALLOC_SIZE);

		if (enable_lua_cache) {
//#ifdef LUA_FILE_CACHING
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
//#endif
		}
	}
}

EVLHTTPRequestHandler::~EVLHTTPRequestHandler()
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	bool enable_lua_cache = config.getBool(SERVER_PREFIX_CFG_NAME + ENABLE_CACHE , true);

	//DEBUGPOINT("ELC = [%d]\n", enable_lua_cache);
	if (enable_lua_cache) {
		lua_pushlightuserdata(_L, (void*) NULL);
		lua_setglobal(_L, "EVLHTTPRequestHandler*");
		lua_gc(_L, LUA_GCCOLLECT, 0);
		lua_settop(_L, 0);
		//DEBUGPOINT("Here _L=[%p] status = [%d]\n", _L);
		if (lua_status(_L) == LUA_OK) enqueue(sg_lua_state_cache._queue, _L); // Cache the lua state so that it can be reused.
		else {
			if (_L) {
				lua_close(_L);
			}
		}
	}
	else {
		//if (!getServer().aborting()) lua_close(_L);
		//DEBUGPOINT("CLOSING [%p] \n", _L);
		lua_close(_L);
	}
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
			case string_body:
				{
					char* str = (char*)(EVLHTTPPartHandler*)it->second;
					free(str);
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

    for ( auto it = _async_tasks.begin(); it != _async_tasks.end(); ++it ) {
		delete it->second;
	}
	_async_tasks.clear();
}

void EVLHTTPRequestHandler::track_async_task(long sr_num, evl_async_task::async_action action, EVHTTPResponse* response)
{
	evl_async_task * task = new evl_async_task();
	task->_task_tracking_state = evl_async_task::SUBMITTED;
	task->_task_action = action;
	task->_response_ptr = response;
	_async_tasks[sr_num] = task;
}

void EVLHTTPRequestHandler::track_async_task(long sr_num, evl_async_task::async_action action, EVHTTPClientSession* session)
{
	evl_async_task * task = new evl_async_task();
	task->_task_tracking_state = evl_async_task::SUBMITTED;
	task->_task_action = action;
	task->_session_ptr = session;
	_async_tasks[sr_num] = task;
}

void EVLHTTPRequestHandler::track_async_task(long sr_num)
{
	evl_async_task * task = new evl_async_task();
	task->_task_tracking_state = evl_async_task::SUBMITTED;
	_async_tasks[sr_num] = task;
}

void EVLHTTPRequestHandler::set_async_task_tracking(long sr_num, evl_async_task::async_task_state st)
{
	async_tasks_t::iterator it = _async_tasks.find(sr_num);
	if (it == _async_tasks.end()) {
		DEBUGPOINT("This must never happen\n");
		return ;
	}

	it->second->_task_tracking_state = st;
	return;
}

evl_async_task::async_task_state EVLHTTPRequestHandler::get_async_task_status(long sr_num)
{
	async_tasks_t::iterator it = _async_tasks.find(sr_num);
	if (it == _async_tasks.end()) {
		return evl_async_task::NOTSTARTED;
	}

	return it->second->_task_tracking_state;
}

EVEventNotification* EVLHTTPRequestHandler::get_async_task_notification(long sr_num)
{
	async_tasks_t::iterator it = _async_tasks.find(sr_num);
	if (it == _async_tasks.end()) {
		return NULL;
	}

	return it->second->_usN;
}

evl_async_task* EVLHTTPRequestHandler::get_async_task(long sr_num)
{
	async_tasks_t::iterator it = _async_tasks.find(sr_num);
	if (it == _async_tasks.end()) {
		return NULL;
	}

	return it->second;
}


void EVLHTTPRequestHandler::send_string_response(int line_no, const char* msg)
{
	if (getEVRHMode() == EVHTTPRequestHandler::SERVER_MODE) {
		Net::HTTPServerRequest* requestPtr = getHTTPRequestPtr();
		if (requestPtr == NULL) {
			DEBUGPOINT("HTTP Request not available");
			std::abort();
		}
		Net::HTTPServerRequest& request = *requestPtr;
		Net::HTTPServerResponse* responsePtr = getHTTPResponsePtr();
		if (responsePtr == NULL) {
			DEBUGPOINT("Response handle is not available");
			std::abort();
		}
		Net::HTTPServerResponse& response = *responsePtr;

		response.setChunkedTransferEncoding(true);
		response.setContentType("text/plain");
		response.setStatusAndReason(Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
		std::ostream& ostr = response.send();

		ostr << "EVLHTTPRequestHandler.cpp:" << line_no << ": " << ((msg)? msg : "nil") << "\n";

		ostr.flush();
	}
	std::string out_msg;
	char s_line_no[10] = {0};
	sprintf(s_line_no, "%d", line_no);
	out_msg = out_msg + "EVLHTTPRequestHandler.cpp:" + s_line_no + ": " + ((msg)? msg : "nil");
	fprintf(stderr, "%s\n", out_msg.c_str());
}

int EVLHTTPRequestHandler::deduceFileToCall()
{
	int status = 0;
	char * cl_inp = getCLRequestPtr()->getBuf();
	if (cl_inp == NULL) { 
		send_string_response(__LINE__, "deduceFileToCall: Command line inputs not present");
		return -1;
	}

	lua_pushstring(_L, cl_inp);
	status = lua_pcall(_L, 1, LUA_MULTRET, 0); 
	if (LUA_OK != status) {
		return -1;
	}

	int n = lua_gettop(_L);
	if (1 > n) {
		send_string_response(__LINE__, "deduceFileToCall: did not return any values");
		return -1;
	}

	for (int i = 1; i <= n ; i++) {
		if (NULL == lua_tostring(_L, i)) {
			send_string_response(__LINE__, "Invalid return value from the mapper script");
			return -1;
		}

		std::string s;
		s = lua_tostring(_L, i);
		_url_parts.push_back(s);
	}

	lua_pop(_L, n);
	return 0;
}

int EVLHTTPRequestHandler::deduceReqHandler()
{
	int status = 0;
	status = lua_pcall(_L, 0, LUA_MULTRET, 0); 
	if (LUA_OK != status) {
		return -1;
	}

	int n = lua_gettop(_L);
	if (2 > n) {
		send_string_response(__LINE__, "map_request_to_handler: did not return values not OK");
		return -1;
	}

	for (int i = 1; i <= n ; i++) {
		if (NULL == lua_tostring(_L, i)) {
			send_string_response(__LINE__, "Invalid return value from the mapper script");
			return -1;
		}

		std::string s;
		s = lua_tostring(_L, i);
		_url_parts.push_back(s);
	}

	if (lua_isnil(_L, 1) || !lua_isstring(_L, 1)) {
		send_string_response(__LINE__, "map_request_to_handler: did not return request handler");
		return -1;
	}
	_request_handler = lua_tostring(_L, 1);

	if ((n>2) && !lua_isnil(_L, 3) && lua_isstring(_L, 3)) {
		_url_part = lua_tostring(_L, 3);
	}
	else {
		_url_part = "handle_request";
	}

	lua_pop(_L, n);

	return 0;
}

int EVLHTTPRequestHandler::loadScriptToExec(std::string script_name)
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	int ret = luaL_loadfile(_L, script_name.c_str());
	if (0 != ret) {
		send_string_response(__LINE__, lua_tostring(_L, -1));
	}
	return ret;
}

int EVLHTTPRequestHandler::loadReqMapper()
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	int ret = luaL_loadfile(_L, _mapping_script.c_str());
	if (0 != ret) {
		send_string_response(__LINE__, lua_tostring(_L, -1));
	}
	return ret;
}

int EVLHTTPRequestHandler::loadReqHandler()
{
	char * path_env = getDeploymentPath();
	std::string s;
	if (!path_env) {
		s = _request_handler;
	}
	else {
		s = s + path_env + "/" + _request_handler;
	}
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	int ret = luaL_loadfile(_L, s.c_str());
	if (0 != ret) {
		send_string_response(__LINE__, lua_tostring(_L, -1));
	}
	return ret;
}

int EVLHTTPRequestHandler::handleRequest()
{
	int status = 0;
	int nargs = 0;
	/* Request object is necessary for deduction of script names
	 * Thus, it is not possible to do this initialization in the 
	 * constructor of this class.
	 * */
	//DEBUGPOINT("Here _L = [%p] fd = [%d] tt=[%d]\n", (void*)_L, getAcceptedSocket()->getSockfd(), getAcceptedSocket()->getTaskType());
	EVAcceptedStreamSocket * tn = getAcceptedSocket();
	if (INITIAL == getState()) {
		int mode = getEVRHMode();
		if ((tn->getTaskType() != EVAcceptedStreamSocket::ASYNC_TASK) &&
			(mode == EVHTTPRequestHandler::SERVER_MODE || mode == EVHTTPRequestHandler::WEBSOCKET_MODE)) {
			if (mode == EVHTTPRequestHandler::SERVER_MODE)
				_mapping_script = getMappingScript(getHTTPRequestPtr());
			else
				_mapping_script = getWSMappingScript(getHTTPRequestPtr());
			//DEBUGPOINT("mode = [%d] Mapping script = [%s]\n", mode, _mapping_script.c_str());
			if (0 != loadReqMapper()) {
				return PROCESSING_ERROR;
			}
			if (0 != deduceReqHandler()) {
				return PROCESSING_ERROR;
			}
			if (0 != loadReqHandler()) {
				return PROCESSING_ERROR;
			}
			int i = 0;
			for (auto it = _url_parts.begin(); it != _url_parts.end(); ++it) {
				i++;
				lua_pushstring(_L, it->c_str());
			}
			nargs=i;
		}
		else {
			//DEBUGPOINT("Here _L = [%p] fd = [%d] tt=[%d]\n",
					//(void*)_L, getAcceptedSocket()->getSockfd(), getAcceptedSocket()->getTaskType());
			_mapping_script = getMappingScript(getCLRequestPtr());
			if (0 != loadReqMapper()) {
				return PROCESSING_ERROR;
			}
			if (0 != deduceFileToCall()) {
				return PROCESSING_ERROR;
			}
			lua_settop(_L, 0);
			int i = 0;
			auto it = _url_parts.begin();
			assert(it != _url_parts.end());
			std::string script_name;
			script_name = std::string(*it);
			/* Prepare function */
			if (0 != loadScriptToExec(script_name)) {
				return PROCESSING_ERROR;
			}
			/* Prepare arguments to function */
			for (++it; it != _url_parts.end(); ++it) {
				lua_pushstring(_L, it->c_str());
				i++;
			}
			nargs=i;
		}
	}
	else {
		Poco::evnet::EVEventNotification &usN = getUNotification();
		async_tasks_t::iterator it = _async_tasks.find(usN.getRefSRNum());
		if (it != _async_tasks.end()) {
			/* The notification is for a task that was initiated in parallel mode
			 * it is possible that the task is being awaited or not.
			 * It it is being awaited, it the yielding function will be the one
			 * waiting for this notification
			 * */
			it->second->_usN = new EVEventNotification(usN);
			if (!getAsyncTaskAwaited()) {
				return PROCESSING;
			}
		}
		else {
			/* A sequential task has completed therefore we have to push
			 * all parallel tasks to unawaited or SUBMITTED state.
			 * *
			 * This is because: Only one of the functions could have yielded,
			 * either a parallel or a sequential one.
			 * If the parallel one has yielded, then control should reach the if block
			 * above (the parallel yield cannot take place while sequential function yeild
			 * is there). Thus control is here means the yielded function is a sequential one
			 * and the notification is for the sequential task.
			 * */
		}
	}

#ifdef DEBUG_NEVER
	{
		Net::HTTPServerResponse* responsePtr = getHTTPResponsePtr();
		Net::HTTPServerResponse& response = *responsePtr;
		response.setChunkedTransferEncoding(true);
		response.setStatusAndReason(Net::HTTPResponse::HTTP_OK);
		response.setContentType("application/json");
		std::ostream& ostr = response.send();
		ostr << "{\"name\":\"His name\", \"age\": 5\"}\n";
		ostr.flush();
		return PROCESSING_COMPLETE;
	}
#endif


	//DEBUGPOINT("Here _L = [%p] fd = [%d] tt=[%d]\n",
	//		(void*)_L, getAcceptedSocket()->getSockfd(), getAcceptedSocket()->getTaskType());
	int nres = 0;
	//status = lua_resume(_L, NULL, nargs, &nres); for lua 5.4.4
	status = lua_resume(_L, NULL, nargs);
	if ((LUA_OK != status) && (LUA_YIELD != status)) {
		//DEBUGPOINT("Here _L = [%p]\n", (void*)_L);
		switch( getEVRHMode()) {
			case EVHTTPRequestHandler::SERVER_MODE:
				//DEBUGPOINT("Here\n");
				if (getAcceptedSocket()->getSockUpgradeTo() == EVAcceptedStreamSocket::NONE) {
					if (getHTTPResponse().sent()) {
						std::ostream& ostr = getHTTPResponse().getOStream();
						ostr << "EVLHTTPRequestHandler.cpp:" << __LINE__ << ": " << lua_tostring(_L, -1) << "\n";
						ostr.flush();
					}
					else {
						send_string_response(__LINE__, lua_tostring(_L, -1));
					}
				}
				{
					/*
					const char * msg = lua_tostring(_L, -1);
					luaL_traceback(_L, _L, msg, 3);
					DEBUGPOINT("%s\n", lua_tostring(_L, -1));
					*/
				}
				//DEBUGPOINT("Here\n");
				break;
			case EVHTTPRequestHandler::COMMAND_LINE_MODE:
				//DEBUGPOINT("Here\n");
				send_string_response(__LINE__, lua_tostring(_L, -1));
				break;
			case EVHTTPRequestHandler::WEBSOCKET_MODE:
				//DEBUGPOINT("Here\n");
				send_string_response(__LINE__, lua_tostring(_L, -1));
			default:
				break;

		}
		//DEBUGPOINT("Here status = [%d]\n", status);
		return PROCESSING_ERROR;
	}
	else if (LUA_YIELD == status) {
		//DEBUGPOINT("Here processing for %d LUA_STATE=[%p]\n", getAccSockfd(), _L);
		return PROCESSING;
	}
	else {
		//DEBUGPOINT("Here\n");
		if (!lua_isnil(_L, -1) && lua_isstring(_L, -1)) {
			//DEBUGPOINT("Here\n");
			std::string output = lua_tostring(_L, -1);
			lua_pop(_L, 1);
			//DEBUGPOINT("Here EVRMode = [%d'\n", getEVRHMode());
			switch( getEVRHMode()) {
				case EVHTTPRequestHandler::SERVER_MODE:
					//DEBUGPOINT("Here\n");
					if (getAcceptedSocket()->getSockUpgradeTo() == EVAcceptedStreamSocket::NONE) {
						//DEBUGPOINT("Here\n");
						if (getHTTPResponse().sent()) {
							std::ostream& ostr = getHTTPResponse().getOStream();
							ostr << "EVLHTTPRequestHandler.cpp:" << __LINE__ << ": " << output.c_str() << "\r\n\r\n";
							ostr.flush();
						}
						else {
							send_string_response(__LINE__, output.c_str());
						}
					}
					//DEBUGPOINT("Here\n");
					break;
				case EVHTTPRequestHandler::COMMAND_LINE_MODE:
					//DEBUGPOINT("Here\n");
					send_string_response(__LINE__, output.c_str());
					break;
				case EVHTTPRequestHandler::WEBSOCKET_MODE:
					//DEBUGPOINT("Here\n");
					send_string_response(__LINE__, output.c_str());
					break;
				default:
					//DEBUGPOINT("Here\n");
					break;
			}
		}
		//DEBUGPOINT("Here complete for %d\n", getAccSockfd());
		return PROCESSING_COMPLETE;
	}
}

Poco::Util::AbstractConfiguration& EVLHTTPRequestHandler::appConfig()
{
	try {
		return Poco::Util::Application::instance().config();
	}
	catch (Poco::NullPointerException&) {
		throw Poco::IllegalStateException(
			"An application configuration is required to initialize the Poco::Net::SSLManager, "
			"but no Poco::Util::Application instance is available."
		);
	}
	catch (std::exception e) {
		DEBUGPOINT("EXCEPTION: Here\n");
		throw e;
	}
}


} } // namespace Poco::evnet
