//
// EVTCPServerConnection.h
//
// Library: Net
// Package: TCPServer
// Module:  EVTCPServerConnection
//
// Definition of the EVTCPServerConnection class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVTCPServerConnection_INCLUDED
#define EVNet_EVTCPServerConnection_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVProcessingState.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Runnable.h"


namespace Poco {
namespace evnet {

using Poco::Net::StreamSocket;


class Net_API EVTCPServerConnection: public Poco::Runnable
	/// The abstract base class for TCP server connections
	/// created by TCPServer.
	///
	/// Derived classes must override the run() method
	/// (inherited from Runnable). Furthermore, a
	/// EVTCPServerConnectionFactory must be provided for the subclass.
	///
	/// The run() method must perform the complete handling
	/// of the client connection. As soon as the run() method
	/// returns, the server connection object is destroyed and
	/// the connection is automatically closed.
	///
	/// A new EVTCPServerConnection object will be created for
	/// each new client connection that is accepted by
	/// TCPServer.
{
public:
	EVTCPServerConnection(StreamSocket& socket);
		/// Creates the EVTCPServerConnection using the given
		/// stream socket.

	virtual ~EVTCPServerConnection();
		/// Destroys the EVTCPServerConnection.

protected:
	StreamSocket& socket();
		/// Returns a reference to the underlying socket.

	void start();
		/// Calls run() and catches any exceptions that
		/// might be thrown by run().

	void start(bool throwExcp);
		/// Calls run() and propagates any exceptions that
		/// might be thrown by run().
	
	virtual EVProcessingState * getProcState() = 0;
		/// Gets the procesing state, if any of the connection,
		/// In order to hold it and continue the same upon
		/// data being available.

	virtual void setProcState(EVProcessingState *) = 0;
		/// Gets the procesing state, if any of the connection,
		/// In order to hold it and continue the same upon
		/// data being available.

private:
	EVTCPServerConnection();
	EVTCPServerConnection(const EVTCPServerConnection&);
	EVTCPServerConnection& operator = (const EVTCPServerConnection&);
	
	StreamSocket &_socket;
	
	friend class EVTCPServerDispatcher;
};


//
// inlines
//
inline StreamSocket& EVTCPServerConnection::socket()
{
	return _socket;
}


} } // namespace Poco::evnet


#endif // EVNet_EVTCPServerConnection_INCLUDED
