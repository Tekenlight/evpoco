//
// EVTCPServerConnectionFactory.h
//
// Library: EVNet
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
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVTCPServerConnection.h"
#include "Poco/SharedPtr.h"
#include "Poco/EVNet/EVProcessingState.h"
#include "Poco/EVNet/EVServer.h"


namespace Poco {
namespace EVNet {


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

	virtual EVProcessingState* createReqProcState(EVServer *) = 0;
		/// Creates an instance of EVHTTPProcessingState
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


} } // namespace Poco::EVNet


#endif // EVNet_EVTCPServerConnectionFactory_INCLUDED
