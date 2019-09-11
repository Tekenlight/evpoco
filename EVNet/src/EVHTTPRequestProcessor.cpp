//
// EVHTTPRequestProcessor.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestProcessor
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <chunked_memory_stream.h>
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPRequestProcessor.h"
#include "Poco/EVNet/EVHTTPServerSession.h"
#include "Poco/EVNet/EVHTTPServerRequestImpl.h"
#include "Poco/EVNet/EVHTTPServerResponseImpl.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/EVNet/EVHTTPRequestHandler.h"
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
using Poco::Net::NetException;

namespace Poco {
namespace EVNet {


EVHTTPRequestProcessor::EVHTTPRequestProcessor(StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory):
	EVTCPServerConnection(socket),
	_pParams(pParams),
	_pFactory(pFactory),
	_stopped(false),
	_reqProcState(0),
	_mem_stream(0)
{
	_mem_stream = 0;
	poco_check_ptr (pFactory);
	
	_pFactory->serverStopped += Poco::delegate(this, &EVHTTPRequestProcessor::onServerStopped);
}

EVHTTPRequestProcessor::EVHTTPRequestProcessor(StreamSocket& socket,
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
	
	_pFactory->serverStopped += Poco::delegate(this, &EVHTTPRequestProcessor::onServerStopped);
}



EVHTTPRequestProcessor::~EVHTTPRequestProcessor()
{
	try
	{
		_pFactory->serverStopped -= Poco::delegate(this, &EVHTTPRequestProcessor::onServerStopped);
	}
	catch (...)
	{
		poco_unexpected();
	}
}

EVProcessingState * EVHTTPRequestProcessor::getProcState()
{
	return _reqProcState;
}

void EVHTTPRequestProcessor::setProcState(EVProcessingState *s)
{
	_reqProcState = (EVHTTPProcessingState *)s;
}


/* This is the event driven equivalent of run method.
 * This method is reentrant.
 * The socket connection is expected to be non-blocking,
 * such that when there is no data to be read (EWOULDBLOCK/EAGAIN)
 * this function will return to the caller. whenever data reading is not
 * complete and the socket fd would block.
 * The caller is expected to call this function agian, when the 
 * socket fd becomes readable. */
void EVHTTPRequestProcessor::evrun()
{
	std::string server = _pParams->getSoftwareVersion();
	EVHTTPServerSession * session = NULL;
	if (_stopped) return ;


	session = _reqProcState->getSession();
	if (!session) {
		session = new EVHTTPServerSession(socket(), _pParams);
		session->setServer(_reqProcState->getServer());
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
			//DEBUGPOINT("Here mems = %p\n",_reqProcState->getResMemStream());
			response->setMemoryStream(_reqProcState->getResMemStream());
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
		if (MESSAGE_COMPLETE > _reqProcState->getState()) {
			/* TBD: 
			 * Pass the state to reading process, in order to retain 
			 * partially read name or value within the reading process.
			 * */
			int ret = _reqProcState->continueRead();
			if (ret < 0) {
				DEBUGPOINT("Here\n");
				sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
				throw NetException("Badly formed HTTP Request");
				return ;
			}
			_reqProcState->setState(ret);
			if (HEADER_READ_COMPLETE <= _reqProcState->getState()) {
				switch (request->getReqType()) {
					case HTTP_HEADER_ONLY:
					case HTTP_FIXED_LENGTH:
					case HTTP_CHUNKED:
						break;
					case HTTP_MULTI_PART:
					case HTTP_MESSAGE_TILL_EOF:
					case HTTP_INVALID_TYPE:
					default:
						DEBUGPOINT("Here\n");
						throw NetException("Unsupported HTTP Request type");
						return;
				}
			}

			if (MESSAGE_COMPLETE > _reqProcState->getState()) {
				//DEBUGPOINT("Here %d\n",c);
				return ;
			}
		}

		try
		{
			EVHTTPRequestHandler * pHandler = _reqProcState->getRequestHandler();
			if (!pHandler) {
				pHandler = _pFactory->createRequestHandler(*request);
				_reqProcState->setRequestHandler(pHandler);

				Poco::Timestamp now;
				response->setDate(now);
				response->setVersion(request->getVersion());
				response->setKeepAlive(_pParams->getKeepAlive() && request->getKeepAlive());
				if (!server.empty())
					response->set("Server", server);

				if (request->getExpectContinue() && response->getStatus() == HTTPResponse::HTTP_OK)
					response->sendContinue();
			}

			if (pHandler) {
				int ret = EVHTTPRequestHandler::PROCESSING;
				ret = pHandler->handleRequest(*request, *response);
				switch (ret) {
					case EVHTTPRequestHandler::PROCESSING_COMPLETE:
					case EVHTTPRequestHandler::PROCESSING_ERROR:
						_reqProcState->setState(PROCESS_COMPLETE);
						break;
					default:
						_reqProcState->setState(REQUEST_PROCESSING);
						break;
				}
				if (_reqProcState->getUpstreamEventQ() &&
						!queue_empty(_reqProcState->getUpstreamEventQ())) {
					void * elem = dequeue(_reqProcState->getUpstreamEventQ());
					while (elem) {
						/* Process upstream events here. */
					}
				}
				session->setKeepAlive(_pParams->getKeepAlive() && response->getKeepAlive());

			}
			else sendErrorResponse(*session, HTTPResponse::HTTP_NOT_IMPLEMENTED);
		}
		catch (Poco::Exception& e)
		{
			if (!response->sent()) {
				try
				{
					DEBUGPOINT("Here\n");
					sendErrorResponse(*session, HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
				}
				catch (...)
				{
				}
			}
			throw e;
		}
		catch (...) {
			DEBUGPOINT("Here\n");
			sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
			throw;
		}
	}
	catch (NoMessageException& e)
	{
		DEBUGPOINT("Here\n");
		sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (MessageException& e)
	{
		DEBUGPOINT("Here\n");
		sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (Poco::Exception& e)
	{
		if (session->networkException())
		{
			DEBUGPOINT("Here\n");
			sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
			session->networkException()->rethrow();
		}
		else { 
			DEBUGPOINT("Here\n");
			sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
			throw e;
		}
	}
	catch (...) {
		DEBUGPOINT("Here\n");
		sendErrorResponse(*session, HTTPResponse::HTTP_BAD_REQUEST);
		throw;
	}
	return ;
}

void EVHTTPRequestProcessor::run()
{
	return evrun();
}

void EVHTTPRequestProcessor::sendErrorResponse(EVHTTPServerSession& session, HTTPResponse::HTTPStatus status)
{
	EVHTTPServerResponseImpl response(session);
	response.setVersion(HTTPMessage::HTTP_1_1);
	response.setStatusAndReason(status);
	response.setKeepAlive(false);
	response.send();
	session.setKeepAlive(false);
}


void EVHTTPRequestProcessor::onServerStopped(const bool& abortCurrent)
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
