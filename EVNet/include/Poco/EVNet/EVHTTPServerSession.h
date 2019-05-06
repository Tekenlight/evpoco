//
// EVHTTPServerSession.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerSession
//
// Definition of the EVHTTPServerSession class.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPServerSession_INCLUDED
#define EVNet_EVHTTPServerSession_INCLUDED


#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/HTTPSession.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Timespan.h"

using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;

namespace Poco {
namespace EVNet {


class Net_API EVHTTPServerSession: public Net::HTTPServerSession
	/// This class handles the server side of a
	/// HTTP session. It is used internally by
	/// HTTPServer.
{
public:
	EVHTTPServerSession(const StreamSocket& socket, HTTPServerParams::Ptr pParams);
		/// Creates the EVHTTPServerSession.
	
	virtual ~EVHTTPServerSession();
		/// Destroys the EVHTTPServerSession.
				
	bool hasMoreRequests();
		/// Returns true if there are requests available.
	
	bool canKeepAlive() const;
		/// Returns true if the session can be kept alive.
		
private:
	bool           _firstRequest;
};


//
// inlines
//
inline bool EVHTTPServerSession::canKeepAlive() const
{
	return true;
}


} } // namespace Poco::EVNet


#endif // EVNet_EVHTTPServerSession_INCLUDED
