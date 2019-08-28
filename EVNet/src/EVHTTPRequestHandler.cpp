//
// EVHTTPRequestHandler.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//
//


#include "Poco/EVNet/EVHTTPRequestHandler.h"


namespace Poco {
namespace EVNet {


EVHTTPRequestHandler::EVHTTPRequestHandler():
	_state(EVHTTPRequestHandler::INITIAL)
{
}


EVHTTPRequestHandler::~EVHTTPRequestHandler()
{
}

EVHTTPRequestHandler::req_proc_state EVHTTPRequestHandler::getState()
{
	return _state;
}

void EVHTTPRequestHandler::setState(EVHTTPRequestHandler::req_proc_state state)
{
	_state = state;
}


} } // namespace Poco::EVNet
