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
		size_t				_message_body_size;
		int					_header_field_in_progress;
		int					_header_value_in_progress;
		std::string			_name;
		std::string			_value;

		resp_msg_parse_state(): _state(0), _msg_body_size(0), _prev_node_ptr(0),
								_content_length(0), _resp_type(HTTP_INVALID_TYPE),
								_tr_encoding_present(0), _message_body_size(0),
								_header_field_in_progress(0), _header_value_in_progress(0) {}

	} ;
	resp_msg_parse_state*	_msg_parse_state;
	std::istream*			_istr;

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
	void formInputStream(chunked_memory_stream * mem_inp_stream);
	std::istream* getStream();

	// Setting of states.
	void messageBegin();
	void appendToName(const char * , size_t, int);
	void appendToValue(const char * , size_t, int);
	void clearName();
	void clearValue();
	void headerComplete();
	void messageComplete();
	void chunkComplete();
	void chunkHeaderComplete();
	void bodyStarted(char * ptr);
};

inline void EVHTTPResponse::messageBegin()
{
	_msg_parse_state->_state = HEADER_NOT_READ;
}

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
	if ((l != 0) && (l != ULLONG_MAX)) {
		_msg_parse_state->_content_length = l;
	}
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

inline std::istream* EVHTTPResponse::getStream()
{
	//poco_check_ptr (_pStream);
	
	return _istr;
}

inline void EVHTTPResponse::appendToName(const char *buf, size_t len, int state)
{
	_msg_parse_state->_header_field_in_progress = state;
	_msg_parse_state->_name.append(buf,len);
	switch (_msg_parse_state->_header_field_in_progress) {
		case 0:
			_msg_parse_state->_value.erase(); // Expecting the next field is value
			break;
		case 1: // Already appended to name, parse is interrupted for want of data.
			break;
		case 2: // Signal is to discard the header field.
			_msg_parse_state->_name.erase();
			break;
		default:
			break;
	}
}

inline void EVHTTPResponse::appendToValue(const char *buf, size_t len, int state)
{
	_msg_parse_state->_header_value_in_progress = state;
	_msg_parse_state->_value.append(buf,len);
	switch (_msg_parse_state->_header_value_in_progress) {
		case 0:
			Poco::trimInPlace(_msg_parse_state->_name);
			Poco::trimInPlace(_msg_parse_state->_value);
			add(_msg_parse_state->_name, decodeWord(_msg_parse_state->_value));
			//printf("%s:%s\n",_name.c_str(), _value.c_str());
			_msg_parse_state->_name.erase();
			_msg_parse_state->_value.erase();
			break;
		case 1: // Already appended to value, parse is interrupted for want of data.
			break;
		case 2: // Signal is to discard the header value.
			_msg_parse_state->_value.erase();
			break;
		default:
			break;
	}

	if (!strcasecmp(_msg_parse_state->_name.c_str(), EVHTTPP_TRANSFER_ENCODING))
		setTrEncodingPresent();
}

inline void EVHTTPResponse::headerComplete()
{
	_msg_parse_state->_state = HEADER_READ_COMPLETE;
}

inline void EVHTTPResponse::messageComplete()
{
	_msg_parse_state->_state = MESSAGE_COMPLETE;
}

} } 

#endif // EVNet_EVHTTPResponse_INCLUDED
