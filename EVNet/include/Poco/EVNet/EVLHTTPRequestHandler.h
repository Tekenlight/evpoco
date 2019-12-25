//
// EVLHTTPRequestHandler.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVLHTTPRequestHandler
//
// Definition of the EVLHTTPRequestHandler class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
// and Contributors.
//
//


#ifndef Net_EVLHTTPRequestHandler_INCLUDED
#define Net_EVLHTTPRequestHandler_INCLUDED

/*
 * This is because lua compiles as ANSI C
 * and evpoco is in C++.
 * Name mangling for lua functions need to be
 * disabled.
 * */
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include "Poco/EVNet/EVHTTPRequestHandler.h"


namespace Poco {
namespace EVNet {

class EVLHTTPRequestHandler;

class Net_API EVLHTTPRequestHandler : public EVHTTPRequestHandler
	/// The HTTP requesthandler implementation that enables
	/// handling of requests using LUA language
	/// created by EVHTTPServer.
	///
{
public:
	EVLHTTPRequestHandler();
		/// Creates the EVLHTTPRequestHandler.

	virtual ~EVLHTTPRequestHandler();
		/// Destroys the EVLHTTPRequestHandler.

	virtual int handleRequest();
		/// Handles the given request.

	virtual std::string getMappingScript(const Net::HTTPServerRequest& request) = 0;
private:
	EVLHTTPRequestHandler(const EVLHTTPRequestHandler&);
	EVLHTTPRequestHandler& operator = (const EVLHTTPRequestHandler&);

	void send_error_response(int line_no, const char * msg);
	int deduceReqHandler();
	int loadReqHandler();
	int loadReqMapper();

	lua_State*		_L;
	lua_State*		_L1;
	std::string		_mapping_script;
	std::string		_request_handler;
};

} } // namespace Poco::EVNet


#endif // Net_EVLHTTPRequestHandler_INCLUDED
