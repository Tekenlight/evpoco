//
//switch (_state) {
//}
// EVHTTPProcessingState.cpp
//
// Library: EVHTTPProcessingState
// Package: evnet
// Module:  EVHTTPProcessingState
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

#include <ev_buffered_stream.h>
#include <istream>


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVHTTPProcessingState.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/NameValueCollection.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Ascii.h"
#include "Poco/String.h"

#include <http_parser.h>

//extern int global_debugging_i;


namespace Poco {
namespace evnet {

using Poco::Net::NetException;
using Poco::Net::MessageException;

EVHTTPProcessingState::EVHTTPProcessingState(EVServer * server):
	EVProcessingState(server),
	_request(0),
	_response(0),
	_session(0),
	_state(HEADER_NOT_READ),
	_header_field_in_progress(0),
	_parser(0),
	_req_memory_stream(0),
	_res_memory_stream(0),
	_tr_encoding_present(0),
	_prev_node_ptr(0),
	_pHandler(0)
{
	_parser = (http_parser*)malloc(sizeof(http_parser));
	memset(_parser,0,sizeof(http_parser));
	_parser->data = (void*)this;
	http_parser_init(_parser,HTTP_REQUEST);
}

EVHTTPProcessingState::~EVHTTPProcessingState()
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
	if (_parser) {
		free(_parser);
		_parser = 0;
	}
	if (_pHandler) {
		delete _pHandler;
		_pHandler = 0;
	}
}

void EVHTTPProcessingState::appendToUri(const char *buf, size_t len)
{
	_uri.append(buf,len);
	_request->setURI(_uri);
}

void EVHTTPProcessingState::appendToName(const char *buf, size_t len, int state)
{
	_header_field_in_progress = state;
	_name.append(buf,len);
	switch (_header_field_in_progress) {
		case 0:
			_value.erase(); // Expecting the next field is value
			break;
		case 1: // Already appended to name, parse is interrupted for want of data.
			break;
		case 2: // Signal is to discard the header field.
			_name.erase();
			break;
		default:
			break;
	}
}

void EVHTTPProcessingState::setTrEncodingPresent()
{
	_tr_encoding_present = 1;
}

bool EVHTTPProcessingState::trEncodingPresent()
{
	return (_tr_encoding_present == 1);
}

void EVHTTPProcessingState::appendToValue(const char *buf, size_t len, int state)
{
	_header_value_in_progress = state;
	_value.append(buf,len);
	switch (_header_value_in_progress) {
		case 0:
			Poco::trimInPlace(_name);
			Poco::trimInPlace(_value);
			_request->add(_name, _request->decodeWord(_value));
			//printf("%s:%s\n",_name.c_str(), _value.c_str());
			_name.erase();
			_value.erase();
			break;
		case 1: // Already appended to value, parse is interrupted for want of data.
			break;
		case 2: // Signal is to discard the header value.
			_value.erase();
			break;
		default:
			break;
	}

	if (!strcasecmp(_name.c_str(), EVHTTPP_TRANSFER_ENCODING))
		setTrEncodingPresent();
}

void EVHTTPProcessingState::setMethod(const char *m)
{
	_request->setMethod(m);
}

void EVHTTPProcessingState::setVersion(const char *v)
{
	_request->setVersion(v);
}

void EVHTTPProcessingState::clearName()
{
	_name.erase();
}

void EVHTTPProcessingState::clearValue()
{
	_value.erase();
}

void EVHTTPProcessingState::headerComplete()
{
	_state = HEADER_READ_COMPLETE;
}

void EVHTTPProcessingState::messageComplete()
{
	_state = MESSAGE_COMPLETE;
}

void EVHTTPProcessingState::messageBegin()
{
	_state = HEADER_NOT_READ;
}

static int message_begin_cb (http_parser *p)
{
	//printf("message_begin_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	e->messageBegin();
	return 0;
}

static int request_url_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("request_url_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);
	
	e->appendToUri(buf, len);
	return 0;
}

static int header_field_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("header_field_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	e->appendToName(buf, len, interrupted);
	return 0;
}

static int header_value_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	//printf("header_value_cb interrupted = %d\n",interrupted);
	e->appendToValue(buf, len, interrupted);
	return 0;
}

static int headers_complete_cb (http_parser *p)
{
	char v[EVHTTPProcessingState::MAX_VERSION_LENGTH+10] = {'\0'};
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	http_version(v, p);
	e->setVersion(v);
	e->setMethod(http_method_str((enum http_method)(p->method)));
	e->headerComplete();

	http_parser_pause(p, 1);

	//printf("headers_complete_cb\n");
	return 0;
}

static int response_status_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("response_status_cb\n");
	return 0;
}

static int body_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("body_cb\n");
	void * ptr = (void*)buf;
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	return 0;
}

static int chunk_header_cb (http_parser *p)
{
	//printf("chunk_header_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	return 0;
}

static int chunk_complete_cb (http_parser *p)
{
	//printf("chunk_complete_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	return 0;
}

static int message_complete_cb (http_parser *p)
{
	//printf("message_complete_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);

	e->messageComplete();
	http_parser_pause(p, 1);

	return 0;
}


void EVHTTPProcessingState::setRequest(EVHTTPServerRequestImpl * req)
{
	_request = req;
}

EVHTTPServerRequestImpl * EVHTTPProcessingState::getRequest()
{
	return _request;
}

void EVHTTPProcessingState::setResponse(EVHTTPServerResponseImpl * resp)
{
	_response = resp;
}

EVHTTPServerResponseImpl * EVHTTPProcessingState::getResponse()
{
	return _response;
}

int EVHTTPProcessingState::getState()
{
	return _state;
}

void EVHTTPProcessingState::setState(int state)
{
	_state = state;
}

void EVHTTPProcessingState::setReqProperties()
{
	if (http_header_only_message(_parser)) {
		_request->setReqType(HTTP_HEADER_ONLY);
	}
	else if (_parser->flags & F_CHUNKED) {
		_request->setReqType(HTTP_CHUNKED);
	}
	else if (_request->getContentLength()) {
		std::string mediaType;
		Poco::Net::NameValueCollection params;
		Poco::Net::MessageHeader::splitParameters(_request->getContentType(), mediaType, params); 
		Poco::trimInPlace(mediaType);
		if (!strncmp("multipart", mediaType.c_str(), 9)) {
			_request->setReqType(HTTP_MULTI_PART);
		}
		else {
			_request->setReqType(HTTP_FIXED_LENGTH);
		}
	}
	else {
		/* RFC 7230, page 33. 3.3.3 point 6
		 * If this is a request message and none of the above
		 * are true, then the message body length is zero
		 * (no message body is present).
		 * */
		_request->setReqType(HTTP_HEADER_ONLY);
	}
}

int EVHTTPProcessingState::continueRead()
{
	char * buffer = NULL;
	size_t parsed = 0;
	http_parser_settings settings = {
		 .on_message_begin = message_begin_cb
		,.on_url = request_url_cb
		,.on_status = response_status_cb
		,.on_header_field = header_field_cb
		,.on_header_value = header_value_cb
		,.on_headers_complete = headers_complete_cb
		,.on_body = body_cb
		,.on_message_complete = message_complete_cb
		,.on_chunk_header = chunk_header_cb
		,.on_chunk_complete = chunk_complete_cb
	};

	size_t len1 = 0, len2 = 0;
	void * nodeptr = NULL;

	moreDataNecessary();
	len2 = _request->getMessageBodySize();

	/* In one pass a node will be either completely consumed
	 * or the message will be complete.
	 * */
	//DEBUGPOINT("_prev_node_ptr = %p\n", _prev_node_ptr);
	if (!_prev_node_ptr)
		nodeptr = _req_memory_stream->get_next(0);
	else
		nodeptr = _req_memory_stream->get_next(_prev_node_ptr);
	//DEBUGPOINT("nodeptr = %p\n", nodeptr);

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
		//DEBUGPOINT("\n%s\n",buffer);
		len2 += http_parser_execute(_parser,&settings, buffer, len1);
		if (_parser->http_errno && (_parser->http_errno != HPE_PAUSED)) {
			DEBUGPOINT("%s\n", http_errno_description((enum http_errno)_parser->http_errno));
			throw NetException(http_errno_description((enum http_errno)_parser->http_errno));
			return -1;
			break;
		}
		//DEBUGPOINT("len2 = %zu\n", len2);
		if (_state < HEADER_READ_COMPLETE) {
			if (len2 < len1) { 
				// Should not happen
				//throw NetException(http_errno_description((enum http_errno)_parser->http_errno));
				DEBUGPOINT("Should not happen %s \n", http_errno_description((enum http_errno)_parser->http_errno));
				return -1;
			}
			/* Have not completed reading the headers and the buffer is completely consumed
			 * */
			_req_memory_stream->erase(len2);
			nodeptr = _req_memory_stream->get_next(0);
			_prev_node_ptr = 0;
			buffer = (char*)_req_memory_stream->get_buffer();
			len1 = _req_memory_stream->get_buffer_len();
			len2 = 0;
		}
		else if (_state == HEADER_READ_COMPLETE) {
			/* Header reading is complete
			 * Buffer may or may not be completely read yet.
			 * */
			_req_memory_stream->erase(len2);

			/* Since the traversed portion is erased
			 * We can start from the next position.
			 * */
			nodeptr = _req_memory_stream->get_next(0);
			_prev_node_ptr = 0;
			buffer = (char*)_req_memory_stream->get_buffer();
			len1 = _req_memory_stream->get_buffer_len();
			len2 = 0;
			http_parser_pause(_parser, 0);
			_state = POST_HEADER_READ_COMPLETE;
			_request->setContentLength(_parser->header_content_length);

			setReqProperties();
			/* ERROR AS PER RFC 7230 3.3.3 point 3. */
			if (trEncodingPresent() && !(_parser->flags & F_CHUNKED)) {
				throw NetException("Bad Request:transfer-encoding present and message not chunked");
				return -1;
			}
			if (HTTP_HEADER_ONLY == _request->getReqType()) {
				_state = MESSAGE_COMPLETE;
				_prev_node_ptr = 0;
				break;
			}
		}
		else if (_state == MESSAGE_COMPLETE) {
			_prev_node_ptr = 0;
			break;
		}
		else {
			_prev_node_ptr = nodeptr;
			nodeptr = _req_memory_stream->get_next(nodeptr);
			buffer = (char*)_req_memory_stream->get_buffer(nodeptr);
			len1 = _req_memory_stream->get_buffer_len(nodeptr);
		}
	}

	if (len2 > 0x10000000) {
		DEBUGPOINT("Will not process messages larger than 10M\n");
		throw NetException("Requests larger than 10M not supported");
		return -1;
	}

	_request->setMessageBodySize(len2);
	if (_state == MESSAGE_COMPLETE) {
		/* This is a hack to circumvent the issue caused by combination of
		 * http_parser_execute when on_headers_complete event is registered and
		 * the strategy  of erasing the header.
		 * The index in http_parser_execute stops at the last character of the header
		 * segment, which is a newline (char 10) and we erase the buffer here till the
		 * previous char.
		 * In such a situation we should erase it by one more char.
		 * */
		int n = 0, c = 0;
		n = _req_memory_stream->copy(0, &c, 1);
		if (n && (c == 10)) {
			_req_memory_stream->erase(1);
		}
		noMoreDataNecessary();
		//DEBUGPOINT("MESSAGE_COMPLETE\n");
		_request->formInputStream(_req_memory_stream);
		memset(_parser,0,sizeof(http_parser));
		_parser->data = (void*)this;
		http_parser_init(_parser,HTTP_REQUEST);
	}

	return _state;
}

void EVHTTPProcessingState::setSession(EVServerSession *session)
{
	_session = session;
}

void EVHTTPProcessingState::setResMemStream(chunked_memory_stream *memory_stream)
{
	_res_memory_stream = memory_stream;
}

void EVHTTPProcessingState::setReqMemStream(chunked_memory_stream *memory_stream)
{
	_req_memory_stream = memory_stream;
}

chunked_memory_stream* EVHTTPProcessingState::getResMemStream()
{
	return _res_memory_stream;
}

chunked_memory_stream* EVHTTPProcessingState::getReqMemStream()
{
	return _req_memory_stream;
}

EVServerSession * EVHTTPProcessingState::getSession()
{
	return _session;
}

EVHTTPRequestHandler * EVHTTPProcessingState::getRequestHandler()
{
	return _pHandler;
}

void EVHTTPProcessingState::setRequestHandler(EVHTTPRequestHandler *pHandler)
{
	_pHandler = pHandler;
}

}
} // End namespace Poco::evnet

