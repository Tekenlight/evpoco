//
// EVTCPServerConnectionFactory.h
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServerConnectionFactory
//
// Definition of the EVTCPServerConnectionFactory class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVTCPServerConnectionFactory_INCLUDED
#define EVNet_EVTCPServerConnectionFactory_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVTCPServerConnection.h"
#include "Poco/SharedPtr.h"
#include "Poco/evnet/EVProcessingState.h"
#include "Poco/evnet/EVServer.h"


namespace Poco {
namespace evnet {


class Net_API EVTCPServerConnectionFactory
	/// A factory for TCPServerConnection objects.
	///
	/// The TCPServer class uses a EVTCPServerConnectionFactory
	/// to create a connection object for each new connection
	/// it accepts.
	///
	/// Subclasses must override the createConnection()
	/// method.
	///
	/// The EVTCPServerConnectionFactoryImpl template class
	/// can be used to automatically instantiate a
	/// EVTCPServerConnectionFactory for a given subclass
	/// of TCPServerConnection.
{
public:
	typedef Poco::SharedPtr<EVTCPServerConnectionFactory> Ptr;
	
	virtual ~EVTCPServerConnectionFactory();
		/// Destroys the EVTCPServerConnectionFactory.

	virtual EVTCPServerConnection* createConnection(StreamSocket& socket) = 0;
		/// Creates an instance of a subclass of TCPServerConnection,
		/// using the given StreamSocket.
		//
	
	// HTTP2 enhancement
	// Add a method to create a message processor based on input message
	//

	virtual EVProcessingState* createReqProcState(EVServer *) = 0;
		/// Creates an instance of EVHTTPProcessingState
	virtual EVProcessingState* createCLProcState(EVServer *) = 0;
		/// Creates an instance of EVCommandLineProcessingState
protected:
	EVTCPServerConnectionFactory();
		/// Creates the EVTCPServerConnectionFactory.

private:
	EVTCPServerConnectionFactory(const EVTCPServerConnectionFactory&);
	EVTCPServerConnectionFactory& operator = (const EVTCPServerConnectionFactory&);
};


template <class S>
class EVTCPServerConnectionFactoryImpl: public EVTCPServerConnectionFactory
	/// This template provides a basic implementation of
	/// EVTCPServerConnectionFactory.
{
public:
	EVTCPServerConnectionFactoryImpl()
	{
	}
	
	~EVTCPServerConnectionFactoryImpl()
	{
	}
	
	EVTCPServerConnection* createConnection(const StreamSocket& socket)
	{
		return new S(socket);
	}
};


} } // namespace Poco::evnet


#endif // EVNet_EVTCPServerConnectionFactory_INCLUDED
