//
// EVCommandLineProcessingState.h
//
// Library: EVCommandLineProcessingState
// Package: evnet
// Module:  EVCommandLineProcessingState
//
// Basic definitions for the Poco evnet library.
// This file must be the first file included by every other evnet
// header file.
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVServerSession.h"
#include "Poco/evnet/EVProcessingState.h"
#include "Poco/evnet/EVCLServerRequestImpl.h"
#include "Poco/evnet/EVCLServerResponseImpl.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/evnet/EVServer.h"
#include <string>

#include <chunked_memory_stream.h>
#include <evpoco/http_parser.h>

#ifndef EVNet_EVCommandLineProcessingState_INCLUDED
#define EVNet_EVCommandLineProcessingState_INCLUDED

namespace Poco {
namespace evnet {

class Net_API EVCommandLineProcessingState : public EVProcessingState
	// This class is used as a marker to hold state data of processing of a request in a connection.
	// In case of event driven model of processing, the processing of a request may have to be
	// suspended mulptiple times, while data is being fetched from sources (e.g. client)
	//
	// The processing of the request is coded in such a way, that all the intermediate data is held within
	// a derivation of this base class and the state is destroyed at the end of processing of the request.
{
public:
	enum Limits
	{
		MAX_METHOD_LENGTH  = 32,
		MAX_URI_LENGTH     = 16384,
		MAX_VERSION_LENGTH = 8
	};

	enum MHLimits
		/// Limits for basic sanity checks when reading a header
	{
		MAX_NAME_LENGTH  = 256,
		MAX_VALUE_LENGTH = 8192,
		DFL_FIELD_LIMIT  = 100
	};

	virtual int getState();
	void setReqMemStream(chunked_memory_stream *);
	void setResMemStream(chunked_memory_stream *);

	void setState(int state);

	EVCommandLineProcessingState(EVServer *);
	virtual ~EVCommandLineProcessingState();

	EVServerSession * getSession();
	void setSession(EVServerSession *);
	void setRequest(EVCLServerRequestImpl * req);
	EVCLServerRequestImpl * getRequest();
	void setResponse(EVCLServerResponseImpl * resp);
	EVCLServerResponseImpl * getResponse();

	int continueRead();
		/// Continues reading of the request status line and header
		/// In case of async processing, a socket might be out of data
		/// in which case the partially read data is held in state and 
		/// reading is continued, when data again becomes available on the
		/// socket
	EVHTTPRequestHandler * getRequestHandler();
	void setRequestHandler(EVHTTPRequestHandler *);
	
	chunked_memory_stream* getReqMemStream();
	chunked_memory_stream* getResMemStream();

private:

	int							_state;
	EVCLServerRequestImpl*		_request;
	EVCLServerResponseImpl*		_response;
	EVServerSession*			_session;
	EVHTTPRequestHandler*		_pHandler;
	chunked_memory_stream*		_req_memory_stream;
	chunked_memory_stream*		_res_memory_stream;
	void*						_prev_node_ptr;
};

}
} // End namespace Poco::evnet





#endif
