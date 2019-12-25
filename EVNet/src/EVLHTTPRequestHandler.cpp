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


namespace Poco {
namespace EVNet {

/*
static int some_func(lua_State* L)
{
	lua_pushstring(L, "THIS_OPERATOR");
	lua_gettable(L, LUA_REGISTRYINDEX);
	uintptr_t this_operator = (uintptr_t)lua_tonumber(L, -1);
	EVLHTTPRequestHandler * req_h = (EVLHTTPRequestHandler*)this_operator;
	lua_pop(L, 1);
	return 0;
}

EVLHTTPRequestHandler::EVLHTTPRequestHandler()
{
	L = luaL_newstate();
	luaL_openlibs(L);

	L1 = lua_newthread(L);
	luaL_openlibs(L1);

	lua_register(L1, "ev_yield", lua_evpoco_yield);

	lua_pushstring(L, "THIS_OPERATOR");
	lua_pushnumber(L, (uintptr_t) this);
	lua_settable(L, LUA_REGISTRYINDEX);

}

*/

static int lua_evpoco_yield(lua_State* L)
{
	//DEBUGPOINT("Here\n");
	return lua_yield(L, 0);
}

static EVLHTTPRequestHandler* get_req_handler_instance(lua_State* L)
{
	lua_getglobal(L, "EVLHTTPRequestHandler*");
	EVLHTTPRequestHandler * req_h = (EVLHTTPRequestHandler*)lua_touserdata(L, -1);
	lua_pop(L, 1);
	return req_h;
}

EVLHTTPRequestHandler::EVLHTTPRequestHandler()
{
	_L = luaL_newstate();
	luaL_openlibs(_L);

	_L1 = lua_newthread(_L);
	luaL_openlibs(_L1);

	lua_register(_L1, "ev_yield", lua_evpoco_yield);

	lua_pushlightuserdata(_L, (void*) this);
	lua_setglobal(_L, "EVLHTTPRequestHandler*");
}

EVLHTTPRequestHandler::~EVLHTTPRequestHandler()
{
	lua_close(_L);
}

void EVLHTTPRequestHandler::send_error_response(int line_no, const char* msg)
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
		DEBUGPOINT("Here\n");
		send_error_response(__LINE__, "map_request_to_handler: function not found");
		return PROCESSING_ERROR;
	}
	status = lua_pcall(_L1, 0, 1, 0); 
	if (LUA_OK != status) {
		return -1;
	}
	if (lua_isnil(_L1, -1) || !lua_isstring(_L1, -1)) {
		DEBUGPOINT("Here\n");
		send_error_response(__LINE__, "map_request_to_handler: function did not return request handler");
		return PROCESSING_ERROR;
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
			send_error_response(__LINE__, lua_tostring(_L1, -1));
			return PROCESSING_ERROR;
		}
		if (0 != deduceReqHandler()) {
			DEBUGPOINT("Here\n");
			send_error_response(__LINE__, lua_tostring(_L1, -1));
			return PROCESSING_ERROR;
		}
		if (0 != loadReqHandler()) {
			DEBUGPOINT("Here\n");
			send_error_response(__LINE__, lua_tostring(_L1, -1));
			return PROCESSING_ERROR;
		}
		lua_getglobal(_L1, "handle_request");
		if (lua_isnil(_L1, -1)) {
			DEBUGPOINT("Here\n");
			send_error_response(__LINE__, "handle_request: function not found");
			return PROCESSING_ERROR;
		}
	}
	status = lua_resume(_L1, NULL, 0);
	if ((LUA_OK != status) && (LUA_YIELD != status)) {
		send_error_response(__LINE__, lua_tostring(_L1, -1));
		return PROCESSING_ERROR;
	}
	else if (LUA_YIELD == status) {
		return PROCESSING;
	}
	else {
		if (!lua_isnil(_L1, -1) && lua_isstring(_L1, -1)) {
			std::string output = lua_tostring(_L1, -1);
			lua_pop(_L1, 1);
			DEBUGPOINT("HELLO %s\n", output.c_str());
			send_error_response(__LINE__, output.c_str());
		}
		else {
			send_error_response(__LINE__, "handle_request: did notreturn any string");
		}
		DEBUGPOINT("Here\n");
		return PROCESSING_COMPLETE;
	}
}


} } // namespace Poco::EVNet
