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
	typedef enum {
		 html_form
		,part_handler
	} mapped_item_type;
	EVLHTTPRequestHandler();
		/// Creates the EVLHTTPRequestHandler.

	virtual ~EVLHTTPRequestHandler();
		/// Destroys the EVLHTTPRequestHandler.

	virtual int handleRequest();
		/// Handles the given request.

	virtual std::string getMappingScript(const Net::HTTPServerRequest& request) = 0;

	void addToComponents(mapped_item_type, void*);
	void* getFromComponents(mapped_item_type);

private:
	EVLHTTPRequestHandler(const EVLHTTPRequestHandler&);
	EVLHTTPRequestHandler& operator = (const EVLHTTPRequestHandler&);

	void send_string_response(int line_no, const char * msg);
	int deduceReqHandler();
	int loadReqHandler();
	int loadReqMapper();
	Poco::EVNet::EVHTTPClientSession session;

	lua_State*								_L0;
	lua_State*								_L;
	std::string								_mapping_script;
	std::string								_request_handler;
	std::string								_request_handler_func;
	std::map<mapped_item_type, void*>		_components;
};

inline void EVLHTTPRequestHandler::addToComponents(mapped_item_type t, void* p)
{
	_components[t] = p;
}

inline void* EVLHTTPRequestHandler::getFromComponents(mapped_item_type t)
{
	return _components[t];
}


} } // namespace Poco::EVNet


#endif // Net_EVLHTTPRequestHandler_INCLUDED
