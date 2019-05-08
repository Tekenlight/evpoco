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


#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPServerConnection.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/EVNet/EVHTTPServerRequestImpl.h"
#include "Poco/EVNet/EVHTTPServerResponseImpl.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/NetException.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Timestamp.h"
#include "Poco/Delegate.h"
#include <memory>

using Poco::Net::HTTPServerSession;
using Poco::Net::NoMessageException;
using Poco::Net::MessageException;
using Poco::Net::HTTPMessage;

namespace Poco {
namespace EVNet {


EVHTTPServerConnection::EVHTTPServerConnection(StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory):
	EVTCPServerConnection(socket),
	_pParams(pParams),
	_pFactory(pFactory),
	_stopped(false),
	_reqProcState(0)
{
	poco_check_ptr (pFactory);
	
	_pFactory->serverStopped += Poco::delegate(this, &EVHTTPServerConnection::onServerStopped);
}

EVHTTPServerConnection::EVHTTPServerConnection(StreamSocket& socket,
												HTTPServerParams::Ptr pParams,
												EVHTTPRequestHandlerFactory::Ptr pFactory,
												EVProcessingState *procState):
	EVTCPServerConnection(socket),
	_pParams(pParams),
	_pFactory(pFactory),
	_stopped(false),
	_reqProcState((EVHTTPProcessingState*)procState)
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

EVProcessingState * EVHTTPServerConnection::getProcState()
{
	return _reqProcState;
}

void EVHTTPServerConnection::setProcState(EVProcessingState *s)
{
	_reqProcState = (EVHTTPProcessingState *)s;
}


/* This is the event driven equivalent of run method.
 * This method is reentrant.
 * The scoekt connection is expected to be non-blocking,
 * such that when there is no data to be read (EWOULDBLOCK/EAGAIN)
 * this function will return to the caller. whenever data reading is not
 * complete and the socket fd would block.
 * The caller is expected to call this function agian, when the 
 * socket fd becomes readable. */
void EVHTTPServerConnection::evrun()
{
	std::string server = _pParams->getSoftwareVersion();
	//printf("%s:%d:%p ref count of impl = %d\n",__FILE__,__LINE__,pthread_self(),
			//socket().impl()->referenceCount());
	HTTPServerSession * session = NULL;
	if (_stopped) return ;

	session = _reqProcState->getSession();
	if (!session) {
		session = new HTTPServerSession(socket(), _pParams);
		_reqProcState->setSession(session);
	}
	session->setSockFdForReuse(true);

	EVHTTPServerResponseImpl *response = 0;
	EVHTTPServerRequestImpl *request = 0;
	try {
		Poco::FastMutex::ScopedLock lock(_mutex);
		request = _reqProcState->getRequest();
		response = _reqProcState->getResponse();
		if (!response) {
			response = new EVHTTPServerResponseImpl(*session);
			_reqProcState->setResponse(response);
		}

		if (!request) {
			request = new EVHTTPServerRequestImpl(*response, *session, _pParams);
			//response->attachRequest(request);
			_reqProcState->setRequest(request);
		}

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
		if (HEADER_READ_COMPLETE > _reqProcState->getState()) {
			/* TBD: 
			 * Pass the state to reading process, in order to retain 
			 * partially read name or value within the reading process.
			 * */
			int ret = _reqProcState->continueRead();
			_reqProcState->setState(ret);
			if (HEADER_READ_COMPLETE > _reqProcState->getState()) {
				return ;
			}
		}

		Poco::Timestamp now;
		response->setDate(now);
		response->setVersion(request->getVersion());
		response->setKeepAlive(_pParams->getKeepAlive() && request->getKeepAlive());
		if (!server.empty())
			response->set("Server", server);
		try
		{
#ifndef POCO_ENABLE_CPP11
			std::auto_ptr<HTTPRequestHandler> pHandler(_pFactory->createRequestHandler(*request));
#else
			std::unique_ptr<HTTPRequestHandler> pHandler(_pFactory->createRequestHandler(*request));
#endif
			if (pHandler.get())
			{
				if (request->getExpectContinue() && response->getStatus() == HTTPResponse::HTTP_OK)
					response->sendContinue();
			
				pHandler->handleRequest(*request, *response);
				/* Setting of state below is provisional.
				 * When the full blown event driven driven request handler is done,
				 * the below will have to be done within the request handler.
				 * */
				_reqProcState->setState(PROCESS_COMPLETE);
				session->setKeepAlive(_pParams->getKeepAlive() && response->getKeepAlive());
			}
			else sendErrorResponse(*session, HTTPResponse::HTTP_NOT_IMPLEMENTED);
		}
		catch (Poco::Exception& e)
		{
			if (!response->sent())
			{
				try
				{
					sendErrorResponse(*session, HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
				}
				catch (...)
				{
				}
			}
			throw e;
		}
		catch (...) {
			throw;
		}
	}
	catch (NoMessageException& e)
	{
		throw e;
	}
	catch (MessageException& e)
	{
		sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (Poco::Exception& e)
	{
		if (session->networkException())
		{
			session->networkException()->rethrow();
		}
		else { 
			throw e;
		}
	}
	catch (...) {
		throw;
	}
	return ;
}

void EVHTTPServerConnection::run()
{
	return evrun();
}
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
/*
void EVHTTPServerConnection::run()
{
	std::string server = _pParams->getSoftwareVersion();
	HTTPServerSession session(socket(), _pParams);
	session.setSockFdForReuse(true);
	if (_stopped) return ;

	try {
		Poco::FastMutex::ScopedLock lock(_mutex);
		EVHTTPServerResponseImpl response(session);
		EVHTTPServerRequestImpl request(response, socket(), _pParams);
		response.attachRequest(&request);

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

	return ;
}
*/


void EVHTTPServerConnection::sendErrorResponse(HTTPServerSession& session, HTTPResponse::HTTPStatus status)
{
	EVHTTPServerResponseImpl response(session);
	response.setVersion(HTTPMessage::HTTP_1_1);
	response.setStatusAndReason(status);
	response.setKeepAlive(false);
	response.send();
	session.setKeepAlive(false);
}


void EVHTTPServerConnection::onServerStopped(const bool& abortCurrent)
{
	printf("%s:%d onserverstopped of Connection\n",__FILE__,__LINE__);
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
