//
// EVCLServerResponseImpl.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVCLServerResponseImpl
//
// Definition of the EVCLServerResponseImpl class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVCLServerResponseImpl_INCLUDED
#define EVNet_EVCLServerResponseImpl_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPRequest.h"

#include "Poco/Net/HTTPServerSession.h"
#include "Poco/evnet/EVServerResponse.h"
#include "Poco/evnet/EVServerSession.h"
#include "Poco/Net/HTTPHeaderStream.h"
#include "Poco/Net/HTTPStream.h"
#include "Poco/Net/HTTPFixedLengthStream.h"
#include "Poco/Net/HTTPChunkedStream.h"

#include "Poco/evnet/EVHTTPHeaderStream.h"
#include "Poco/evnet/EVHTTPStream.h"
#include "Poco/evnet/EVHTTPFixedLengthStream.h"
#include "Poco/evnet/EVHTTPChunkedStream.h"

#include "Poco/File.h"
#include "Poco/Timestamp.h"
#include "Poco/NumberFormatter.h"
#include "Poco/StreamCopier.h"
#include "Poco/CountingStream.h"
#include "Poco/Exception.h"
#include "Poco/FileStream.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"

#include <chunked_memory_stream.h>

using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerSession;
using Poco::Net::HTTPHeaderOutputStream;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPFixedLengthOutputStream;
using Poco::Net::HTTPHeaderOutputStream;
using Poco::Net::HTTPChunkedOutputStream;
using Poco::Net::HTTPFixedLengthOutputStream;
using Poco::Net::HTTPOutputStream;
using Poco::Net::HTTPHeaderOutputStream;

namespace Poco {
	namespace Net {
		class HTTPServerSession;
	}
namespace evnet {


class EVCLServerRequestImpl;


class Net_API EVCLServerResponseImpl: public EVServerResponse
{
public:
	enum EVCL_RETURN_STATUS {
		OK = 0,
		ERROR = 1
	};

	EVCLServerResponseImpl(EVCLServerRequestImpl *request,EVServerSession& session);
		/// Creates the EVCLServerResponseImpl.

	EVCLServerResponseImpl(EVServerSession& session);
		/// Creates the EVCLServerResponseImpl.

	~EVCLServerResponseImpl();
		/// Destroys the EVCLServerResponseImpl.
	void attachSession(EVServerSession &session);

	void attachRequest(EVCLServerRequestImpl* pRequest);

	void setReturnStatus(int status);
	int getReturnStatus();
	void setMemoryStream(chunked_memory_stream* cms);

private:
	EVServerSession&			_session;
	EVCLServerRequestImpl*		_pRequest;
	int							_status;
	chunked_memory_stream*		_out_memory_stream;

	friend class EVCLServerRequestImpl;
};


//
// inlines

inline void EVCLServerResponseImpl::setMemoryStream(chunked_memory_stream* cms)
{
	if (!_out_memory_stream) _out_memory_stream = cms;
}

inline void EVCLServerResponseImpl::setReturnStatus(int status)
{
	_status = status;
}

inline int EVCLServerResponseImpl::getReturnStatus()
{
	return _status;
}

inline void EVCLServerResponseImpl::attachSession(EVServerSession & session)
{
	_session = session;
}

inline void EVCLServerResponseImpl::attachRequest(EVCLServerRequestImpl* pRequest)
{
	_pRequest = pRequest;
}


} } // namespace Poco::evnet


#endif // EVNet_EVCLServerResponseImpl_INCLUDED
