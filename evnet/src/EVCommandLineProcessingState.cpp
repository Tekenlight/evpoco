//
//switch (_state) {
//}
// EVCommandLineProcessingState.cpp
//
// Library: EVCommandLineProcessingState
// Package: evnet
// Module:  EVCommandLineProcessingState
//
// Basic definitions for the Poco evnet library.
// This file must be the first file included by every other evnet
// header file.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include <ev_buffered_stream.h>
#include <istream>


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVCommandLineProcessingState.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/NameValueCollection.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Ascii.h"
#include "Poco/String.h"

#include <evpoco/http_parser.h>

//extern int global_debugging_i;


namespace Poco {
namespace evnet {

using Poco::Net::NetException;
using Poco::Net::MessageException;

EVCommandLineProcessingState::EVCommandLineProcessingState(EVServer * server):
	EVProcessingState(server),
	_request(0),
	_response(0),
	_session(0),
	_state(HEADER_NOT_READ),
	_req_memory_stream(0),
	_res_memory_stream(0),
	_pHandler(0),
	_prev_node_ptr(0)
{
}

EVCommandLineProcessingState::~EVCommandLineProcessingState()
{
	if (_request) {
		delete _request;
		_request = NULL;
	}
	if (_response) {
		delete _response;
		_response = NULL;
	}
	if (_session) {
		delete _session;
		_session = NULL;
	}
	if (_pHandler) {
		delete _pHandler;
		_pHandler = 0;
	}
}

void EVCommandLineProcessingState::setRequest(EVCLServerRequestImpl * req)
{
	_request = req;
}

EVCLServerRequestImpl * EVCommandLineProcessingState::getRequest()
{
	return _request;
}

void EVCommandLineProcessingState::setResponse(EVCLServerResponseImpl * resp)
{
	_response = resp;
}

EVCLServerResponseImpl * EVCommandLineProcessingState::getResponse()
{
	return _response;
}

int EVCommandLineProcessingState::getState()
{
	return _state;
}

void EVCommandLineProcessingState::setState(int state)
{
	_state = state;
}

int EVCommandLineProcessingState::continueRead()
{
	char * buffer = NULL;
	size_t parsed = 0;
	size_t len1 = 0, len2 = 0;
	len2 = _request->getMessageBodySize();
	void * nodeptr = NULL;

	moreDataNecessary();
	if (!_prev_node_ptr)
		nodeptr = _req_memory_stream->get_next(0);
	else
		nodeptr = _req_memory_stream->get_next(_prev_node_ptr);

	buffer = (char*)_req_memory_stream->get_buffer(nodeptr);
	len1 = _req_memory_stream->get_buffer_len(nodeptr);

	if (buffer == NULL) {
		setNewDataNotProcessed();
		return _state;
	}
	else {
		setNewDataProcessed();
	}

	while (1) {
		if (NULL == buffer) {
			//DEBUGPOINT("Coming out of loop _prev_node_ptr = %p\n", _prev_node_ptr);
			break;
		}
		for (int i = 0; i < len1; i++) {
			len2 += 1;
			if (buffer[i] == '\n') {
				_state = MESSAGE_COMPLETE;
				break;
			}
		}
		if (MESSAGE_COMPLETE == _state) break;
		nodeptr = _req_memory_stream->get_next(nodeptr);
		buffer = (char*)_req_memory_stream->get_buffer(nodeptr);
		len1 = _req_memory_stream->get_buffer_len(nodeptr);
	}

	if (_state < MESSAGE_COMPLETE) _request->setMessageBodySize(len2);
	if (_state == MESSAGE_COMPLETE) {
		noMoreDataNecessary();
		char * buf = (char*)malloc(len2 + 1);
		memset(buf, 0, (len2+1));
		_req_memory_stream->read(buf, len2);
		assert(buf[len2-1] == '\n');
		_request->setMessageBodySize(len2-1);
		buf[len2-1] = '\0';
		_request->setBuf(buf);
	}

	return _state;
}

void EVCommandLineProcessingState::setSession(EVServerSession *session)
{
	_session = session;
}

void EVCommandLineProcessingState::setResMemStream(chunked_memory_stream *memory_stream)
{
	_res_memory_stream = memory_stream;
}

void EVCommandLineProcessingState::setReqMemStream(chunked_memory_stream *memory_stream)
{
	_req_memory_stream = memory_stream;
}

chunked_memory_stream* EVCommandLineProcessingState::getResMemStream()
{
	return _res_memory_stream;
}

chunked_memory_stream* EVCommandLineProcessingState::getReqMemStream()
{
	return _req_memory_stream;
}

EVServerSession * EVCommandLineProcessingState::getSession()
{
	return _session;
}

EVHTTPRequestHandler * EVCommandLineProcessingState::getRequestHandler()
{
	return _pHandler;
}

void EVCommandLineProcessingState::setRequestHandler(EVHTTPRequestHandler *pHandler)
{
	_pHandler = pHandler;
}

}
} // End namespace Poco::evnet

