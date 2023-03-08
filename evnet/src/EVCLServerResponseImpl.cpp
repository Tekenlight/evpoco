//
// EVCLServerResponseImpl.cpp
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVCLServerResponseImpl
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVCLServerResponseImpl.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"
#include "Poco/evnet/evnet.h"

using Poco::File;
using Poco::Timestamp;
using Poco::NumberFormatter;
using Poco::StreamCopier;
using Poco::OpenFileException;
using Poco::DateTimeFormatter;
using Poco::DateTimeFormat;


namespace Poco {
namespace evnet {


EVCLServerResponseImpl::EVCLServerResponseImpl(EVCLServerRequestImpl * request,EVServerSession& session):
	_session(session),
	_pRequest(request),
	_status(0),
	_out_memory_stream(0)
{
}

EVCLServerResponseImpl::EVCLServerResponseImpl(EVServerSession& session):
	_session(session),
	_pRequest(0),
	_status(0),
	_out_memory_stream(0)
{
}

EVCLServerResponseImpl::~EVCLServerResponseImpl()
{
	//_session.getServer()->dataReadyForSend(_session.socket().impl()->sockfd());
	char str_ret_value[128] = {0};
	memset(str_ret_value, 0, 128);
	sprintf(str_ret_value, "%d", _status);
	char * buf = (char*)malloc(strlen(str_ret_value));
	strncpy(buf, str_ret_value, strlen(str_ret_value));
	_out_memory_stream->push(buf, strlen(str_ret_value));
}

} } // namespace Poco::evnet
