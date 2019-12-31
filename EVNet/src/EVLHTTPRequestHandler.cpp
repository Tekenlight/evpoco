//
// EVLHTTPRequestHandler.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVLHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//


#include "Poco/EVNet/EVLHTTPRequestHandler.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTMLForm.h"


namespace Poco {
namespace EVNet {

const static char *_html_form_type_name = "htmlform";
const static char *_http_req_type_name = "httpreq";
const static char *_http_resp_type_name = "httpresp";
const static char *_platform_name = "context";

static EVLHTTPRequestHandler* get_req_handler_instance(lua_State* L)
{
	lua_getglobal(L, "EVLHTTPRequestHandler*");
	EVLHTTPRequestHandler * req_h = (EVLHTTPRequestHandler*)lua_touserdata(L, -1);
	lua_pop(L, 1);
	return req_h;
}

static int obj__gc(lua_State *L)
{
	return 0;
}

static int evpoco_parse_form(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else {
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
		Net::HTMLForm *form = NULL;
		try {
			//form1 = new Net::HTMLForm(request, request.stream(), partHandler);
			form = new Net::HTMLForm(request, request.stream());
		} catch (std::exception& ex) {
			DEBUGPOINT("CHA %s\n",ex.what());
			throw(ex);
		}
		reqHandler->addToReqComponents(EVLHTTPRequestHandler::html_form, form);

		void * ptr = lua_newuserdata(L, sizeof(Net::HTMLForm*));
		*((Net::HTMLForm**)ptr) = form;
		luaL_setmetatable(L, _html_form_type_name);
	}

	return 1;
}

static int evpoco_get_http_host(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else {
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
		std::string host = request.getHost();
		lua_pushstring(L, host.c_str());
	}

	return 1;
}

static int evpoco_get_http_uri(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else {
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
		std::string uri = request.getURI();
		lua_pushstring(L, uri.c_str());
	}

	return 1;
}

static int evpoco_get_http_method(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else {
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
		std::string method = request.getMethod();
		lua_pushstring(L, method.c_str());
	}

	return 1;
}

static int evpoco_get_request_header(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
		lua_pushnil(L);
	}
	else {
		const char* hdr_fld_name = lua_tostring(L, -1);
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -2));
		std::string hdr_fld_value = request.get(hdr_fld_name, "");
		lua_pushstring(L, hdr_fld_value.c_str());
	}

	return 1;
}

static int evpoco_get_request_headers(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else {
		Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
		lua_newtable (L);
		Poco::Net::NameValueCollection::ConstIterator it = request.begin();
		Poco::Net::NameValueCollection::ConstIterator end = request.end();
		for (; it != end; ++it) {
			lua_pushstring(L, it->second.c_str());
			lua_setfield(L, -2, it->first.c_str());
		}
	}

	return 1;
}

static int evpoco_yield(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	return lua_yield(L, 0);
}

static int evpoco_get_form_field(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Net::HTTPServerRequest& request = reqHandler->getRequest();
	//DEBUGPOINT("Here\n");
	if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
		lua_pushnil(L);
	}
	else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
		DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
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

struct form_iterator {
	Poco::Net::NameValueCollection::ConstIterator it;
	Poco::Net::NameValueCollection::ConstIterator last;
};

static int evpoco_begin_iteration(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
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

static int evpoco_next_iteration(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
		lua_pushnil(L);
		lua_pushnil(L);
	}
	else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
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

static int evpoco_get_request(lua_State* L)
{
	EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Net::HTTPServerRequest& request = reqHandler->getRequest();

	void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerRequest*));
	*(Net::HTTPServerRequest**)ptr = &request;
	luaL_setmetatable(L, _http_req_type_name);

	return 1;
}

static int evpoco_open_lua_lib(lua_State* L)
{
	static const luaL_Reg form_lib[] = {
		{ "get_form_field", &evpoco_get_form_field },
		{ "begin_iteration", &evpoco_begin_iteration},
		{ "next_iteration", &evpoco_next_iteration},
		{ NULL, NULL }
	};

	static const luaL_Reg evpoco_http_req_lib[] = {
		{ "get_http_hdr_field", &evpoco_get_request_header },
		{ "get_http_hdr_fields", &evpoco_get_request_headers },
		{ "get_http_method", &evpoco_get_http_method },
		{ "get_http_uri", &evpoco_get_http_uri },
		{ "get_http_host", &evpoco_get_http_host },
		{ "parse_http_req_form", &evpoco_parse_form },
		{ NULL, NULL }
	};

	static const luaL_Reg evpoco_lib[] = {
		{ "get_request", &evpoco_get_request },
		{ NULL, NULL }
	};

	luaL_newlib(L, evpoco_lib); //Stack: context

	// Stack: context
	luaL_newmetatable(L, _http_req_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_http_req_lib); // Stack: context meta http_req
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

EVLHTTPRequestHandler::EVLHTTPRequestHandler()
{
	_L = luaL_newstate();
	luaL_openlibs(_L);

	_L1 = lua_newthread(_L);
	luaL_openlibs(_L1);

	lua_register(_L1, "ev_yield", evpoco_yield);
	luaL_requiref(_L1, _platform_name, &evpoco_open_lua_lib, 1);

	lua_pushlightuserdata(_L1, (void*) this);
	lua_setglobal(_L1, "EVLHTTPRequestHandler*");
}

EVLHTTPRequestHandler::~EVLHTTPRequestHandler()
{
	lua_close(_L);
    for ( std::map<mapped_item_type, void*>::iterator it = _req_components.begin(); it != _req_components.end(); ++it ) {
		switch (it->first) {
			case html_form:
				{
					Net::HTMLForm* form = (Net::HTMLForm*)it->second;
					delete form;
				}
				break;
			default:
				break;
		}
    }
    _req_components.clear();
}

void EVLHTTPRequestHandler::send_string_response(int line_no, const char* msg)
{
	Net::HTTPServerRequest& request = (getRequest());
	Net::HTTPServerResponse& response = (getResponse());

	response.setChunkedTransferEncoding(true);
	response.setContentType("text/plain");
	std::ostream& ostr = getResponse().send();

	ostr << "EVLHTTPRequestHandler.cpp:" << line_no << ": " << msg << "\n";

	ostr.flush();
}

int EVLHTTPRequestHandler::deduceReqHandler()
{
	int status = 0;
	lua_getglobal(_L1, "map_request_to_handler");
	if (lua_isnil(_L1, -1)) {
		send_string_response(__LINE__, "map_request_to_handler: function not found");
		return -1;
	}
	status = lua_pcall(_L1, 0, 1, 0); 
	if (LUA_OK != status) {
		DEBUGPOINT("Here %s\n", lua_tostring(_L1, -1));
		return -1;
	}
	if (lua_isnil(_L1, -1) || !lua_isstring(_L1, -1)) {
		send_string_response(__LINE__, "map_request_to_handler: function did not return request handler");
		return -1;
	}
	_request_handler = lua_tostring(_L1, -1);
	lua_pop(_L1, 1);
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
	return luaL_dofile(_L1, _mapping_script.c_str());
}

int EVLHTTPRequestHandler::loadReqHandler()
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	return luaL_dofile(_L1, _request_handler.c_str());
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
			send_string_response(__LINE__, lua_tostring(_L1, -1));
			return PROCESSING_ERROR;
		}
		if (0 != deduceReqHandler()) {
			DEBUGPOINT("Here\n");
			return PROCESSING_ERROR;
		}
		if (0 != loadReqHandler()) {
			DEBUGPOINT("Here\n");
			send_string_response(__LINE__, lua_tostring(_L1, -1));
			return PROCESSING_ERROR;
		}
		lua_getglobal(_L1, "handle_request");
		if (lua_isnil(_L1, -1)) {
			DEBUGPOINT("Here\n");
			send_string_response(__LINE__, "handle_request: function not found");
			return PROCESSING_ERROR;
		}
	}
	status = lua_resume(_L1, NULL, 0);
	if ((LUA_OK != status) && (LUA_YIELD != status)) {
		send_string_response(__LINE__, lua_tostring(_L1, -1));
		return PROCESSING_ERROR;
	}
	else if (LUA_YIELD == status) {
		if (0 > makeNewHTTPConnection(std::bind(&EVLHTTPRequestHandler::handleRequest, this), "localhost", 9980, session)) {
			send_string_response(__LINE__,"Could not connect to echo server");
			return PROCESSING_ERROR;
		}
		return PROCESSING;
	}
	else {
		if (!lua_isnil(_L1, -1) && lua_isstring(_L1, -1)) {
			std::string output = lua_tostring(_L1, -1);
			lua_pop(_L1, 1);
			send_string_response(__LINE__, output.c_str());
		}
		else {
			send_string_response(__LINE__, "handle_request: did not return any string");
		}
		return PROCESSING_COMPLETE;
	}
}


} } // namespace Poco::EVNet
