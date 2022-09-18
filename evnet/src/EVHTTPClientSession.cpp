//
// EVHTTPClientSession.cpp
//
// Library: evnet
// Package: EVHTTPClient
// Module:  EVHTTPClientSession
//
// Copyright (c) 2019-2020, Tekenlight Solutions and contributors
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVHTTPClientSession.h"

namespace Poco {
namespace evnet {

void EVHTTPClientSession::parser_init(EVHTTPResponse * response_ptr)
{
	_parser = (http_parser*)malloc(sizeof(http_parser));
	memset(_parser,0,sizeof(http_parser));
	_parser->data = response_ptr;
	http_parser_init(_parser,HTTP_RESPONSE);
}

EVHTTPClientSession::EVHTTPClientSession(Net::StreamSocket& sock, Net::SocketAddress &addr):
	_sock(sock),
	_addr(addr),
	_state(NOT_CONNECTED),
	_parser(0),
	_send_stream(0),
	_recv_stream(0),
	_acc_fd(-1),
	_index(-1)
{
	parser_init(0);
}

EVHTTPClientSession::EVHTTPClientSession():
	_state(NOT_CONNECTED),
	_parser(0),
	_send_stream(0),
	_recv_stream(0),
	_acc_fd(-1),
	_index(-1)
{
	parser_init(0);
}

EVHTTPClientSession::~EVHTTPClientSession()
{
	if (_parser) free(_parser); _parser = 0;
}

static int message_begin_cb (http_parser *p)
{
	//printf("message_begin_cb\n");
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	e->messageBegin();
	return 0;
}

static int request_url_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("request_url_cb\n");
	/*
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);
	
	e->appendToUri(buf, len);
	*/
	return 0;
}

static int response_status_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("response_status_cb\n");
	// Use p->http->major, and p->http->minor for version
	// Use p->status_code for response status
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);
	return 0;
}

static int header_field_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("header_field_cb\n");
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	e->appendToName(buf, len, interrupted);
	return 0;
}

static int header_value_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	//printf("header_value_cb interrupted = %d\n",interrupted);
	e->appendToValue(buf, len, interrupted);
	return 0;
}

static int headers_complete_cb (http_parser *p)
{
	char v[EVHTTPResponse::MAX_VERSION_LENGTH+10] = {'\0'};
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	http_version(v, p);
	e->setVersion(v);
	EVHTTPResponse::HTTPStatus status_code = (EVHTTPResponse::HTTPStatus)p->status_code;
	e->setStatusAndReason(status_code);
	e->headerComplete();

	http_parser_pause(p, 1);

	//printf("headers_complete_cb\n");
	return 0;
}

static int body_cb (http_parser *p, const char *buf, size_t len, int interrupted)
{
	//printf("body_cb\n");
	/*
	void * ptr = (void*)buf;
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	e->bodyStarted((char*)ptr);

	*/
	return 0;
}

static int chunk_header_cb (http_parser *p)
{
	//printf("chunk_header_cb\n");
	//EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	//e->chunkHeaderComplete();
	//http_parser_pause(p, 1);
	return 0;
}

static int chunk_complete_cb (http_parser *p)
{
	//printf("chunk_complete_cb\n");
	//EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	//e->chunkComplete();
	//http_parser_pause(p, 1);

	return 0;
}

static int message_complete_cb (http_parser *p)
{
	//printf("message_complete_cb\n");
	EVHTTPResponse * e = (EVHTTPResponse *)(p->data);

	e->messageComplete();
	http_parser_pause(p, 1);

	return 0;
}

void EVHTTPClientSession::setRespProperties(EVHTTPResponse& response)
{
	if (http_header_only_message(_parser)) {
		response.setRespType(HTTP_HEADER_ONLY);
	}
	else if (_parser->flags & F_CHUNKED) {
		response.setRespType(HTTP_CHUNKED);
	}
	else if (response.getContentLength()) {
		std::string mediaType;
		Poco::Net::NameValueCollection params;
		Poco::Net::MessageHeader::splitParameters(response.getContentType(), mediaType, params); 
		Poco::trimInPlace(mediaType);
		if (!strncmp("multipart", mediaType.c_str(), 9)) {
			response.setRespType(HTTP_MULTI_PART);
		}
		else {
			response.setRespType(HTTP_FIXED_LENGTH);
		}
	}
	else {
		/* RFC 7230, page 33. 3.3.3 point 7
		 * Otherwise, this is a response message without a declared message
		 * body length, so the message body length is determined by the
		 * number of octets received prior to the server closing the
		 * connection.
		 * */
		response.setRespType(HTTP_MESSAGE_TILL_EOF);
	}
}

int EVHTTPClientSession::http_parser_hack()
{
	/* This is a hack to circumvent the issue caused by combination of
	 * http_parser_execute when on_headers_complete event is registered and
	 * the strategy  of erasing the header.
	 * The index in http_parser_execute stops at the last character of the header
	 * segment, which is a newline (char 10) and we erase the buffer here till the
	 * previous char.
	 * In such a situation we should erase it by one more char.
	 * */
	int n = 0, c = 0, reduction_count = 0;
	n = _recv_stream->copy(0, &c, 1);
	//DEBUGPOINT("Found c = %c\n", c);
	if (n && (c == 10)) {
		_recv_stream->erase(1);
		reduction_count = 1;
	}
	return reduction_count;
}

int EVHTTPClientSession::continueRead(EVHTTPResponse& response)
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

	if (!(_parser->data)) _parser->data = (void*)&response;
	len2 = response.getMessageBodySize();
	if (!(response.getPrevNodePtr()))
		nodeptr = _recv_stream->get_next(0);
	else
		nodeptr = _recv_stream->get_next(response.getPrevNodePtr());

	/* In one pass a node will be either completely consumed
	 * or the message will be complete.
	 * */

	buffer = (char*)_recv_stream->get_buffer(nodeptr);
	len1 = _recv_stream->get_buffer_len(nodeptr);
	if (!buffer) return response.getParseState();
	while (1) {
		if (NULL == buffer) {
			//DEBUGPOINT("Coming out of loop _prev_node_ptr = %p\n", response.getPrevNodePtr());
			break;
		}

		len2 += http_parser_execute(_parser,&settings, buffer, len1);
		if (_parser->http_errno && (_parser->http_errno != HPE_PAUSED)) {
			char * buf_for_dump = (char*)malloc(len1+1);
			memset(buf_for_dump, 0, len1+1);
			memcpy(buf_for_dump, buffer, len1);
			DEBUGPOINT("============================================================\n");
			DEBUGPOINT("%s\n", buf_for_dump);
			DEBUGPOINT("============================================================\n");
			free(buf_for_dump);
			DEBUGPOINT("%s\n", http_errno_description((enum http_errno)_parser->http_errno));
			DEBUGPOINT("\n%s\n", buffer);
			response.clear();
			response.initParseState();
			parser_init(&response);
			setState(IN_ERROR);
			return -1;
		}

		if (response.getParseState() < HEADER_READ_COMPLETE) {
			if (len2 < len1) { 
				// Should not happen
				//throw NetException(http_errno_description((enum http_errno)_parser->http_errno));
				DEBUGPOINT("Should not happen %s \n", http_errno_description((enum http_errno)_parser->http_errno));
				response.clear();
				response.initParseState();
				parser_init(&response);
				setState(IN_ERROR);
				return -1;
			}
			/* Have not completed reading the headers and the buffer is completely consumed
			 * */
			_recv_stream->erase(len2);
			nodeptr = _recv_stream->get_next(0);
			response.setPrevNodePtr(0);
			buffer = (char*)_recv_stream->get_buffer();
			len1 = _recv_stream->get_buffer_len();
			len2 = 0;
		}
		else if (HEADER_READ_COMPLETE == response.getParseState()) {
			/* Header reading is complete
			 * Buffer may or may not be completely read yet.
			 * */
			_recv_stream->erase(len2);

			/* Since the traversed portion is erased
			 * We can start from the next position.
			 * */
			nodeptr = _recv_stream->get_next(0);
			response.setPrevNodePtr(0);
			buffer = (char*)_recv_stream->get_buffer();
			len1 = _recv_stream->get_buffer_len();
			len2 = 0;
			http_parser_pause(_parser, 0);
			response.setParseState(POST_HEADER_READ_COMPLETE);
			response.setEVContentLength(_parser->header_content_length);
			setRespProperties(response);
			if (response.trEncodingPresent() && !(_parser->flags & F_CHUNKED)) {
			/* CONDITION AS PER RFC 7230 3.3.3 point 3. */
			/* Our design choice: We dont want to process endless messages. */
				DEBUGPOINT("Bad Response:transfer-encoding present and message not chunked\n");
				DEBUGPOINT("Bad Response: Cannot handle messages that have to be read till EOF\n");
				response.clear();
				response.initParseState();
				parser_init(&response);
				setState(IN_ERROR);
				return -1;
			}
			else if (HTTP_MESSAGE_TILL_EOF == response.getRespType()) {
				/* Our design choice: We dont want to process endless messages. */
				DEBUGPOINT("Bad Response: Cannot handle messages that have to be read till EOF\n");
				response.clear();
				response.initParseState();
				parser_init(&response);
				setState(IN_ERROR);
				return -1;
			}

			if (HTTP_HEADER_ONLY == response.getRespType()) {
				if (response.getStatus() == EVHTTPResponse::HTTP_CONTINUE) {
					//DEBUGPOINT("GOT A CONTINUATION RESPONSE, restarting the parsing\n");
					//DEBUGPOINT("\n%s\n", buffer);
					response.clear();
					response.initParseState();
					parser_init(&response);
					len2 = response.getMessageBodySize();
					//len2 = 0; Restart parse length.
				}
				else {
					http_parser_hack();
					response.setParseState(MESSAGE_COMPLETE);
					response.setPrevNodePtr(0);
					break;
				}
			}
		}
		else if (response.getParseState() == MESSAGE_COMPLETE) {
			response.setPrevNodePtr(0);
			len2 -= http_parser_hack();
			break;
		}
		else {
			response.setPrevNodePtr(nodeptr);
			nodeptr = _recv_stream->get_next(nodeptr);
			buffer = (char*)_recv_stream->get_buffer(nodeptr);
			len1 = _recv_stream->get_buffer_len(nodeptr);
		}
	}
	response.setMessageBodySize(len2);
	if (MESSAGE_COMPLETE == response.getParseState()) {
		response.formInputStream(_recv_stream);
		parser_init(0);
	}

	return response.getParseState();
}


} } // namespace Poco::evnet
