//
// EVCLServerRequestImpl.cpp
//
// Library: evnet
// Package: HTTPServer
// Module:  EVCLServerRequestImpl
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVCLServerRequestImpl.h"


using Poco::icompare;


namespace Poco {
namespace evnet {

/*
 * TBD:
 *
 * This needs to be totally repared.
 * Usage of session on the server side is quite unnecessary.
 * IO handling of request has to be event driven and neeed not be buffered.
 *
 * */
EVCLServerRequestImpl::EVCLServerRequestImpl(EVCLServerResponseImpl& response,
													EVServerSession& session):
													
	_response(response),
	_session(session),
	_message_body_size(0),
	_buf(0)
{
	response.attachRequest(this);
}

EVCLServerRequestImpl::~EVCLServerRequestImpl()
{
	if (_buf) delete _buf;
}


} } // namespace Poco::evnet
