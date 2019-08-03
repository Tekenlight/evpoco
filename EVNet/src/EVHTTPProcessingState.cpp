//
// EVHTTPProcessingState.cpp
//
// Library: EVHTTPProcessingState
// Package: EVNet
// Module:  EVHTTPProcessingState
//
// Basic definitions for the Poco EVNet library.
// This file must be the first file included by every other EVNet
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


#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPProcessingState.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/NameValueCollection.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Ascii.h"
#include "Poco/String.h"


namespace Poco {
namespace EVNet {

void EVHTTPProcessingState::appendToUri(const char *buf, size_t len)
{
	_uri.append(buf,len);
}

void EVHTTPProcessingState::appendToName(const char *buf, size_t len, int state)
{
	_header_field_in_progress = state;
	_name.append(buf,len);
	if (!_header_field_in_progress) _value.erase();
}

int EVHTTPProcessingState::getHeaderFieldInProgress()
{
	return _header_field_in_progress;
}

void EVHTTPProcessingState::appendToValue(const char *buf, size_t len)
{
	_value.append(buf,len);
}

void EVHTTPProcessingState::setMethod(const char *m)
{
	_request->setMethod(m);
}

void EVHTTPProcessingState::setVersion(const char *v)
{
	_request->setVersion(_version);
}

void EVHTTPProcessingState::clearName()
{
	_name.erase();
}

void EVHTTPProcessingState::clearValue()
{
	_value.erase();
}

static int message_begin_cb (http_parser *p)
{
	printf("message_begin_cb\n");
	return 0;
}

static int header_field_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	printf("header_field_cb\n");
	return 0;
}

static int header_value_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	printf("header_value_cb\n");
	return 0;
}

static int request_url_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	printf("request_url_cb\n");
	EVHTTPProcessingState * e = (EVHTTPProcessingState *)(p->data);
	
	e->appendToUri(buf, len);
	return 0;
}

static int headers_complete_cb (http_parser *p)
{
	printf("headers_complete_cb\n");
	return 0;
}

static int message_complete_cb (http_parser *p)
{
	printf("message_complete_cb\n");
	http_parser_pause(p, 1);
	//http_parser_pause(p, 0);
	return 0;
}

static int response_status_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	printf("response_status_cb\n");
	return 0;
}

static int body_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	printf("body_cb\n");
	return 0;
}

static int chunk_header_cb (http_parser *p)
{
	printf("chunk_header_cb\n");
	return 0;
}

static int chunk_complete_cb (http_parser *p)
{
	printf("chunk_complete_cb\n");
	return 0;
}

using Poco::Net::NetException;
using Poco::Net::MessageException;

EVHTTPProcessingState::EVHTTPProcessingState():
	_request(0),
	_response(0),
	_session(0),
	_state(HEADER_NOT_READ),
	_subState(READ_START),
	_fields(0),
	_header_field_in_progress(0)
{
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

std::string EVHTTPProcessingState::getCurName()
{
	return _name;
}

void EVHTTPProcessingState::setCurName(std::string name)
{
	_name = name;
}

std::string EVHTTPProcessingState::getcurValue()
{
	return _value;
}

void EVHTTPProcessingState::setCurValue(std::string value)
{
	_value = value;
}

int EVHTTPProcessingState::readByte(int * chptr)
{
	int ret = 0;
	int fd = _session->socket().impl()->sockfd();
	errno = 0;
	ret = recv(fd, chptr, 1 , 0);
	if ((ret <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			//DEBUGPOINT("%d:%s\n",errno,strerror(errno));
			return 0;
		}
		else {
			const char * error_string = NULL;
			if (!errno) {
				error_string = "Peer closed connection";
			}
			else {
				error_string = strerror(errno);
			}
			throw NetException(error_string);
			return -1;
		}
	}
	return 1;
}

#define readch(inpptr,retstate) {\
	int ret = readByte(inpptr); \
	if (ret <= 0) {\
		return retstate; \
	}\
}

int EVHTTPProcessingState::readStatusLine()
{
	int ch = 0;
	_method.reserve(16);
    _uri.reserve(64);
    _version.reserve(16);

	/* From the RFC
	 * Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
	 * */
	/* Reading of HTTP Request / HTTP Message / HTTP Header begins here. */
	/* Read the status line . */
	readch(&ch,_state);
	switch (_subState) {
		case READ_START:
			_subState = METHOD_READ_IN_PROGRESS;
		case METHOD_READ_IN_PROGRESS:
			while (Poco::Ascii::isSpace(ch)) readch(&ch,_state);
			_subState = METHOD_READ_PART_ONE_COMPLETE;
		case METHOD_READ_PART_ONE_COMPLETE:
			while (!Poco::Ascii::isSpace(ch) && _method.length() < MAX_METHOD_LENGTH) {
				_method += (char) ch;
				readch(&ch,_state);
			}
			if (!Poco::Ascii::isSpace(ch)) throw MessageException("HTTP request method invalid or too long");
			_request->setMethod(_method);
			_subState = URI_READ_IN_PROGRESS;
		case URI_READ_IN_PROGRESS:
			while (Poco::Ascii::isSpace(ch)) readch(&ch,_state);
			_subState = URI_READ_PART_ONE_COMPLETE;
		case URI_READ_PART_ONE_COMPLETE:
			while (!Poco::Ascii::isSpace(ch) && _uri.length() < MAX_URI_LENGTH) {
				_uri += (char) ch;
				readch(&ch,_state);
			}
			if (!Poco::Ascii::isSpace(ch)) throw MessageException("HTTP request URI invalid or too long");
			_request->setURI(_uri);
			_subState = VERSION_READ_IN_PROGRESS;
		case VERSION_READ_IN_PROGRESS:
			while (Poco::Ascii::isSpace(ch)) readch(&ch,_state);
			_subState = VERSION_READ_PART_ONE_COMPLETE;
		case VERSION_READ_PART_ONE_COMPLETE:
			while (!Poco::Ascii::isSpace(ch) && _version.length() < MAX_VERSION_LENGTH) {
				_version += (char) ch;
				readch(&ch,_state);
			}
			if (!Poco::Ascii::isSpace(ch)) { throw MessageException("Invalid HTTP version string"); }
			_request->setVersion(_version);
			_subState = VERSION_READ_COMPLETE;
		case VERSION_READ_COMPLETE:
			while (ch != '\n') { readch(&ch,_state) }
			_subState = READ_START;
			_state = STATUS_LINE_READ;
			break;
	}

	return _state;
}

int EVHTTPProcessingState::continueReadReqHeader()
{
	int ch = 0;
	bool endofheader = false;
	readch(&ch,_state);
	/*
	if (READ_START == _subState) {
		_subState = NAME_READ_IN_PROGRESS; _name.clear(); _value.clear();
		if (ch != '\r' && ch != '\n') endofheader = true;
	}
	*/
	while (!endofheader) {
		if (_fields >= DFL_FIELD_LIMIT) {
			throw MessageException("Too many header fields");
		}
		switch (_subState) {
			case READ_START:
				if (ch == '\r' || ch == '\n') {  endofheader = true; break; }
				_subState = NAME_READ_IN_PROGRESS; _name.clear(); _value.clear();
			case NAME_READ_IN_PROGRESS:
				while (ch != ':' && ch != '\n' && _name.length() < MAX_NAME_LENGTH) { _name += ch; readch(&ch,_state); }
				_subState = NAME_READ_PART_ONE_COMPLETE;
			case NAME_READ_PART_ONE_COMPLETE:
				_subState = NAME_READ_PART_TWO_COMPLETE;
				// ignore invalid header lines and start all over again
				if (ch == '\n') { _name.clear(); _value.clear(); _subState = READ_START; readch(&ch,_state); continue; }
			case NAME_READ_PART_TWO_COMPLETE:
				// No white char after name in header line
				if (ch != ':') throw MessageException("Field name too long/no colon found");
				_subState = VALUE_READ_IN_PROGRESS;
				readch(&ch,_state);
			case VALUE_READ_IN_PROGRESS:
				while (Poco::Ascii::isSpace(ch) && ch != '\r' && ch != '\n') { readch(&ch,_state);}
				_subState = VALUE_READ_PART_ONE_COMPLETE;
			case VALUE_READ_PART_ONE_COMPLETE:
				while (ch != '\r' && ch != '\n' && _value.length() < MAX_VALUE_LENGTH) { _value += ch; readch(&ch,_state); }
				_subState = VALUE_READ_PART_TWO_COMPLETE;
			case VALUE_READ_PART_TWO_COMPLETE:
				_subState = VALUE_READ_PART_THREE_COMPLETE;
				if (ch == '\r') readch(&ch,_state);
			case VALUE_READ_PART_THREE_COMPLETE:
				_subState = VALUE_READ_PART_FOUR_COMPLETE;
				if (ch != '\n') throw MessageException("Field value too long/no CRLF found");
				readch(&ch,_state);
			case VALUE_READ_PART_FOUR_COMPLETE:
				if (ch == ' ' || ch == '\t') {
					_subState = VALUE_READ_PART_FIVE_COMPLETE;
				}
				else {
					_subState = VALUE_READ_PART_NINE_COMPLETE;
					Poco::trimRightInPlace(_value);
					_request->add(_name, _request->decodeWord(_value));
					_fields++;
					break;
				}
			case VALUE_READ_PART_FIVE_COMPLETE:
				while (ch != '\r' && ch != '\n' && _value.length() < MAX_VALUE_LENGTH) { _value += ch; readch(&ch,_state); }
				_subState = VALUE_READ_PART_SIX_COMPLETE;
			case VALUE_READ_PART_SIX_COMPLETE:
				_subState = VALUE_READ_PART_SEVEN_COMPLETE;
				if (ch == '\r') readch(&ch,_state);
			case VALUE_READ_PART_SEVEN_COMPLETE:
				_subState = VALUE_READ_PART_EIGHT_COMPLETE;
				if (ch != '\n') throw MessageException("Folded field value too long/no CRLF found");
				readch(&ch,_state);
			case VALUE_READ_PART_EIGHT_COMPLETE:
				_subState = VALUE_READ_PART_FOUR_COMPLETE;
				break;
			case VALUE_READ_PART_NINE_COMPLETE:
				/* This happens because previous readch could not complete and
				 * thus this is coming from the top of this function. */
				break;
			default:
				throw MessageException("Invalid message format");
				break;
		}
		/* _subState became part nine complete because, it encountered a LF while reading value. */
		/* If there is a CR of LF after LF, it is the end of header. */
		if (_subState == VALUE_READ_PART_NINE_COMPLETE) {
			if (ch == '\r' || ch == '\n') {
				endofheader = true;
			}
			_subState = READ_START;
		}
	}
	while (ch != '\n') readch(&ch,_state);

	_state = HEADER_READ_COMPLETE;

	return _state;
}

/*
int EVHTTPProcessingState::continueRead()
{
	//DEBUGPOINT("_state = [%d] _subState = [%d]\n",_state, _subState);
	switch (_state) {
		case HEADER_NOT_READ:
			if (readStatusLine() != STATUS_LINE_READ) break;
		case STATUS_LINE_READ:
			if (continueReadReqHeader() != HEADER_READ_COMPLETE) break;
			_request->formInputStream();
		case HEADER_READ_COMPLETE:
			break;
		default:
			break;
	}
	//DEBUGPOINT("_state = [%d] _subState = [%d]\n",_state, _subState);

	return _state;
}
*/

int EVHTTPProcessingState::continueRead()
{
	//DEBUGPOINT("_state = [%d] _subState = [%d]\n",_state, _subState);
	char * buffer = NULL;
	size_t len = 0;
	while (1) {
		buffer = (char*)_memory_stream.get_buffer();
		len = _memory_stream.get_buffer_len();
		if (NULL == buffer) {
			break;
		}
	}
	//DEBUGPOINT("_state = [%d] _subState = [%d]\n",_state, _subState);

	return _state;
}

void EVHTTPProcessingState::setSession(HTTPServerSession *session)
{
	_session = session;
	fcntl(_session->socket().impl()->sockfd(), F_SETFL, O_NONBLOCK);

	// All this code is hack
	ssize_t bytes = 1024;
	char * buffer = (char*)malloc(1024);
	int fd = _session->socket().impl()->sockfd();
	errno = 0;
	bytes = recv(fd, buffer, 1024 , 0);
	if ((bytes <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			//DEBUGPOINT("%d:%s\n",errno,strerror(errno));
			return ;
		}
		else {
			const char * error_string = NULL;
			if (!errno) {
				error_string = "Peer closed connection";
			}
			else {
				error_string = strerror(errno);
			}
			throw NetException(error_string);
			return ;
		}
	}
	_memory_stream.push(buffer, (size_t)bytes);
}

HTTPServerSession * EVHTTPProcessingState::getSession()
{
	return _session;
}


}
} // End namespace Poco::EVNet
