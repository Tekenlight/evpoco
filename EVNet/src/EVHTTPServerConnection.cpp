//
// EVHTTPServerConnection.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerConnection
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPServerConnection.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/Net/HTTPServerRequestImpl.h"
#include "Poco/Net/HTTPServerResponseImpl.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/NetException.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Timestamp.h"
#include "Poco/Delegate.h"
#include <memory>

using Poco::Net::HTTPServerSession;
using Poco::Net::HTTPServerResponseImpl;
using Poco::Net::HTTPServerRequestImpl;
using Poco::Net::NoMessageException;
using Poco::Net::MessageException;
using Poco::Net::HTTPMessage;

namespace Poco {
namespace EVNet {


EVHTTPServerConnection::EVHTTPServerConnection(const StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory):
	TCPServerConnection(socket),
	_pParams(pParams),
	_pFactory(pFactory),
	_stopped(false)
{
	poco_check_ptr (pFactory);
	
	_pFactory->serverStopped += Poco::delegate(this, &EVHTTPServerConnection::onServerStopped);
}


EVHTTPServerConnection::~EVHTTPServerConnection()
{
	try
	{
		_pFactory->serverStopped -= Poco::delegate(this, &EVHTTPServerConnection::onServerStopped);
	}
	catch (...)
	{
		poco_unexpected();
	}
}


void EVHTTPServerConnection::run()
{
	std::string server = _pParams->getSoftwareVersion();
	HTTPServerSession session(socket(), _pParams);
	session.setSockFdForReuse(true);
	if (!_stopped) {
		try {
			Poco::FastMutex::ScopedLock lock(_mutex);
			if (!_stopped) {
				HTTPServerResponseImpl response(session);
				/* REF: HTTP RFC
				 * Request       =	Request-Line
									*(( general-header
									 | request-header
									 | entity-header ) CRLF)
									CRLF
									[ message-body ]
				 * */
				/* This construction will land in read method of HTTPRequest.cpp
				 * Which will read the status-line plus the header fields of the HTTP
				 * request.
				 * */
				HTTPServerRequestImpl request(response, session, _pParams);

				Poco::Timestamp now;
				response.setDate(now);
				response.setVersion(request.getVersion());
				response.setKeepAlive(_pParams->getKeepAlive() && request.getKeepAlive());
				if (!server.empty())
					response.set("Server", server);
				try
				{
#ifndef POCO_ENABLE_CPP11
					std::auto_ptr<HTTPRequestHandler> pHandler(_pFactory->createRequestHandler(request));
#else
					std::unique_ptr<HTTPRequestHandler> pHandler(_pFactory->createRequestHandler(request));
#endif
					if (pHandler.get())
					{
						if (request.getExpectContinue() && response.getStatus() == HTTPResponse::HTTP_OK)
							response.sendContinue();
					
						pHandler->handleRequest(request, response);
						session.setKeepAlive(_pParams->getKeepAlive() && response.getKeepAlive());
					}
					else sendErrorResponse(session, HTTPResponse::HTTP_NOT_IMPLEMENTED);
				}
				catch (Poco::Exception&)
				{
					if (!response.sent())
					{
						try
						{
							sendErrorResponse(session, HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
						}
						catch (...)
						{
						}
					}
					throw;
				}
			}
		}
		catch (NoMessageException&)
		{
			throw;
		}
		catch (MessageException&)
		{
			sendErrorResponse(session, HTTPResponse::HTTP_BAD_REQUEST);
		}
		catch (Poco::Exception&)
		{
			if (session.networkException())
			{
				session.networkException()->rethrow();
			}
			else { 
				throw;
			}
		}
	}
}


void EVHTTPServerConnection::sendErrorResponse(HTTPServerSession& session, HTTPResponse::HTTPStatus status)
{
	HTTPServerResponseImpl response(session);
	response.setVersion(HTTPMessage::HTTP_1_1);
	response.setStatusAndReason(status);
	response.setKeepAlive(false);
	response.send();
	session.setKeepAlive(false);
}


void EVHTTPServerConnection::onServerStopped(const bool& abortCurrent)
{
	_stopped = true;
	if (abortCurrent)
	{
		try
		{
			// Note: On Windows, select() will not return if one of its socket is being
			// shut down. Therefore we have to call close(), which works better.
			// On other platforms, we do the more graceful thing.
#if defined(_WIN32)
			socket().close();
#else
			socket().shutdown();
#endif
		}
		catch (...)
		{
		}
	}
	else
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		try
		{
#if defined(_WIN32)
			socket().close();
#else
			socket().shutdown();
#endif
		}
		catch (...)
		{
		}
	}
}


} } // namespace Poco::EVNet
