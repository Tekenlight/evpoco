//
// EVHTTPResponse.h
//
// Library: EVNet
// Package: HTTPServer
// Module:  EVHTTPResponse
//
// Definition of the EVHTTPResponse class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#ifndef EVNet_EVHTTPResponse_INCLUDED
#define EVNet_EVHTTPResponse_INCLUDED

#include <istream>
#include <chunked_memory_stream.h>
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/HTTPResponse.h"

namespace Poco {
namespace EVNet {

class Net_API EVHTTPResponse: public Net::HTTPResponse
	/// This subclass of HTTPResponse is used for
	/// representing client-side HTTP requests.
	///
{
private:
	class resp_msg_parse_state {
		public:
		int					_state;
		size_t				_msg_body_size;
		void*				_prev_node_ptr;
		unsigned long		_content_length;
		HTTP_REQ_TYPE_ENUM	_resp_type;
		int					_tr_encoding_present;
		resp_msg_parse_state(): _state(0), _msg_body_size(0), _prev_node_ptr(0),
								_content_length(0), _resp_type(HTTP_INVALID_TYPE),
								_tr_encoding_present(0) {}
	} ;
	resp_msg_parse_state* _msg_parse_state;

public:
	EVHTTPResponse();
	~EVHTTPResponse();
	void initParseState();
	void clear();

	void setContentLength(unsigned long l);
	unsigned long getContentLength();
	void setParseState(int state);
	int getParseState();
	void setMessageBodySize(size_t size);
	size_t getMessageBodySize();
	void setPrevNodePtr(void * p);
	void* getPrevNodePtr();
	void setRespType(HTTP_REQ_TYPE_ENUM);
	HTTP_REQ_TYPE_ENUM getRespType();
	void setTrEncodingPresent();
	bool trEncodingPresent();
};

inline void EVHTTPResponse::setPrevNodePtr(void * p)
{
	_msg_parse_state->_prev_node_ptr = p;
}

inline void * EVHTTPResponse::getPrevNodePtr()
{
	return _msg_parse_state->_prev_node_ptr;
}

inline void EVHTTPResponse::setRespType(HTTP_REQ_TYPE_ENUM r)
{
	_msg_parse_state->_resp_type = r;
}

inline HTTP_REQ_TYPE_ENUM EVHTTPResponse::getRespType()
{
	return _msg_parse_state->_resp_type;
}

inline void EVHTTPResponse::setContentLength(unsigned long l)
{
	_msg_parse_state->_content_length = l;
}

inline unsigned long EVHTTPResponse::getContentLength()
{
	return _msg_parse_state->_content_length;
}

inline void EVHTTPResponse::setParseState(int state)
{
	_msg_parse_state->_state = state;
}

inline int EVHTTPResponse::getParseState()
{
	return _msg_parse_state->_state;
}

inline void EVHTTPResponse::setMessageBodySize(size_t size)
{
	_msg_parse_state->_msg_body_size = size;
}

inline size_t EVHTTPResponse::getMessageBodySize()
{
	return _msg_parse_state->_msg_body_size;
}

inline void EVHTTPResponse::setTrEncodingPresent()
{
	_msg_parse_state->_tr_encoding_present = 1;
}

inline bool EVHTTPResponse::trEncodingPresent()
{
	return (_msg_parse_state->_tr_encoding_present == 1);
}

} } 

#endif // EVNet_EVHTTPResponse_INCLUDED
