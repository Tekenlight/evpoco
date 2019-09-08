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
	_state(INITIAL)
{
}


EVHTTPRequestHandler::~EVHTTPRequestHandler()
{
}

int EVHTTPRequestHandler::getState()
{
	return _state;
}

void EVHTTPRequestHandler::setState(int state)
{
	_state = state;
}


} } // namespace Poco::EVNet
