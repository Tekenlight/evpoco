//
// EVServerSession.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVServerSession
//
// Definition of the EVServerSession class.
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVServerSession_INCLUDED
#define EVNet_EVServerSession_INCLUDED


#include <chunked_memory_stream.h>
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVServer.h"
#include "Poco/Net/HTTPSession.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Timespan.h"

using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;

namespace Poco {
namespace evnet {


class Net_API EVServerSession : public Net::HTTPServerSession
	/// This class handles the server side of a
	/// HTTP session. It is used internally by
	/// HTTPServer.
{
public:
	EVServerSession(const StreamSocket& socket, HTTPServerParams::Ptr pParams);
		/// Creates the EVServerSession.
	
	virtual ~EVServerSession();
		/// Destroys the EVServerSession.
				
	EVServer* getServer();
	void setServer(EVServer * server);

private:
	bool           _firstRequest;
	chunked_memory_stream *_mem_stream;
	EVServer* _server;
};


//
// inlines
//

} } // namespace Poco::evnet


#endif // EVNet_EVServerSession_INCLUDED
