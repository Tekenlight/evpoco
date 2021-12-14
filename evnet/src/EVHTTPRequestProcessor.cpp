//
// EVHTTPRequestProcessor.cpp
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPRequestProcessor
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt. Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <chunked_memory_stream.h>
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVHTTPRequestProcessor.h"
#include "Poco/evnet/EVServerSession.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"
#include "Poco/evnet/EVHTTPServerResponseImpl.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"
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
namespace evnet {


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
	_reqProcState(procState)
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
	_reqProcState = s;
}

/* This is the event driven equivalent of run method.
 * This method is reentrant.
 * The socket connection is expected to be non-blocking,
 * such that when there is no data to be read (EWOULDBLOCK/EAGAIN)
 * this function will return to the caller. whenever data reading is not
 * complete and the socket fd would block.
 * The caller is expected to call this function agian, when the 
 * socket fd becomes readable. */
void EVHTTPRequestProcessor::procCLReq(EVCommandLineProcessingState *reqProcState)
{
	std::string server = _pParams->getSoftwareVersion();
	EVServerSession * session = NULL;
	if (_stopped) return ;


	EVCLServerResponseImpl *response = 0;
	EVCLServerRequestImpl *request = 0;

	try {
		Poco::FastMutex::ScopedLock lock(_mutex);
		session = reqProcState->getSession();
		if (!session) {
			session = new EVServerSession(socket(), _pParams);
			session->setServer(reqProcState->getServer());
			reqProcState->setSession(session);
		}
		/* To prevent Poco library from closing the socket. */
		session->setSockFdForReuse(true);

	} catch (std::exception e) {
		DEBUGPOINT("EXCEPTION: Here %s for %d\n", e.what(), socket().impl()->sockfd());
		throw;
	}

	request = static_cast<EVCLServerRequestImpl *>(reqProcState->getRequest());
	response = static_cast<EVCLServerResponseImpl *>(reqProcState->getResponse());
	try {
		if (!response) {
			response = new EVCLServerResponseImpl(*session);
			response->setMemoryStream(reqProcState->getResMemStream());
			reqProcState->setResponse(response);
		}
	} catch (...) {
		DEBUGPOINT("EXCEPTION: Here %p\n", reqProcState->getResponse());
		throw;
	}

	try {
		if (!request) {
			request = new EVCLServerRequestImpl(*response, *session);
			reqProcState->setRequest(request);
		}
	} catch (...) {
		DEBUGPOINT("EXCEPTION: Here %p\n", reqProcState->getRequest());
		throw;
	}

	try {
		Poco::FastMutex::ScopedLock lock(_mutex);

		if (MESSAGE_COMPLETE > reqProcState->getState()) {
			int ret = reqProcState->continueRead();
			if (ret < 0) {
				DEBUGPOINT("EXCEPTION: Here\n");
				sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
				throw NetException("Badly formed Request");
				return ;
			}
			reqProcState->setState(ret);
			if (MESSAGE_COMPLETE > reqProcState->getState()) {
				return ;
			}
		}

		try {
			EVHTTPRequestHandler * pHandler = reqProcState->getRequestHandler();
			if (!pHandler) {
				try {
					pHandler = _pFactory->createRequestHandler(*request);
					reqProcState->setRequestHandler(pHandler);
					pHandler->setServer(reqProcState->getServer());
					pHandler->setAccSockfd(socket().impl()->sockfd());
					pHandler->setAcceptedSocket(getAcceptedSocket());
					pHandler->setCLRequest(request);
					pHandler->setCLResponse(response);
					pHandler->setEVRHMode(reqProcState->getMode());

					if (pHandler) {
						int ret = EVHTTPRequestHandler::PROCESSING;
						ret = pHandler->handleRequestSurrogateInitial();
						if (ret<0) ret = EVHTTPRequestHandler::PROCESSING_ERROR;
						switch (ret) {
							case EVHTTPRequestHandler::PROCESSING:
								reqProcState->setState(REQUEST_PROCESSING);
								break;
							case EVHTTPRequestHandler::PROCESSING_COMPLETE:
							case EVHTTPRequestHandler::PROCESSING_ERROR:
							default:
								reqProcState->setState(PROCESS_COMPLETE);
								break;
						}
						if (ret == EVHTTPRequestHandler::PROCESSING_ERROR) {
							response->setReturnStatus(1);
						}
					}
					else sendErrorResponse(*response, HTTPResponse::HTTP_NOT_IMPLEMENTED);
				}
				catch (Exception e) {
					DEBUGPOINT("EXCEPTION: Here\n");
					throw e;
				}
				catch (std::exception e) {
					DEBUGPOINT("EXCEPTION: Here\n");
					char msg[100] = {0};
					sprintf(msg, "%s:%d UNKNOWN EXCEPTION",__FILE__, __LINE__);
					throw Exception(msg);
				}
			}
			else {
				if (reqProcState->getUpstreamEventQ() &&
						!queue_empty(reqProcState->getUpstreamEventQ())) {
					void * elem = dequeue(reqProcState->getUpstreamEventQ());
					bool processing_complete = false;
					while (!processing_complete && elem) {
						/* Process upstream events here. */
						std::unique_ptr<EVUpstreamEventNotification> usN((EVUpstreamEventNotification*)elem);
						try {
							pHandler->setState(usN->getCBEVIDNum());
							pHandler->setUNotification(usN.get());
							{
								int ret = EVHTTPRequestHandler::PROCESSING;
								ret = pHandler->handleRequestSurrogate();
								if (ret<0) ret = EVHTTPRequestHandler::PROCESSING_ERROR;
								switch (ret) {
									case EVHTTPRequestHandler::PROCESSING:
										reqProcState->setState(REQUEST_PROCESSING);
										break;
									case EVHTTPRequestHandler::PROCESSING_COMPLETE:
									case EVHTTPRequestHandler::PROCESSING_ERROR:
									default:
										processing_complete = true;
										reqProcState->setState(PROCESS_COMPLETE);
										break;
								}
								if (ret == EVHTTPRequestHandler::PROCESSING_ERROR) {
									response->setReturnStatus(1);
								}
							}
						}
						catch (Exception e) {
							DEBUGPOINT("EXCEPTION: Here\n");
							throw e;
						}
						catch (std::exception e) {
							DEBUGPOINT("EXCEPTION: Here\n");
							char msg[100] = {0};
							sprintf(msg, "%s:%d UNKNOWN EXCEPTION",__FILE__, __LINE__);
							throw Exception(msg);
						}
						//elem = NULL;
						elem = dequeue(reqProcState->getUpstreamEventQ());
						//if (elem) DEBUGPOINT("Found additional queued event\n");
					}
				}
			}
		}
		catch (Poco::Exception& e) {
			try {
				DEBUGPOINT("EXCEPTION: Here\n");
				sendErrorResponse(*response, HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
			}
			catch (...) {
				DEBUGPOINT("EXCEPTION: Here\n");
			}
			DEBUGPOINT("EXCEPTION: Here\n");
			throw e;
		}
		catch (...) {
			DEBUGPOINT("EXCEPTION: Here\n");
			sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
			throw;
		}
	}
	catch (NoMessageException& e)
	{
		DEBUGPOINT("EXCEPTION: Here\n");
		sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (MessageException& e)
	{
		DEBUGPOINT("EXCEPTION: Here\n");
		sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (Poco::Exception& e)
	{
		if (session->networkException())
		{
			DEBUGPOINT("EXCEPTION: Here\n");
			if (0 == e.code()) sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
			else if (HTTPResponse::HTTP_VERSION_NOT_SUPPORTED == e.code())
				sendErrorResponse(*response, (HTTPResponse::HTTPStatus)e.code());
			else sendErrorResponse(*response, (HTTPResponse::HTTPStatus)e.code());
			session->networkException()->rethrow();
		}
		else { 
			DEBUGPOINT("EXCEPTION: Here %s %d\n", e.what(), e.code());
			if (0 == e.code()) sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
			else if (HTTPResponse::HTTP_VERSION_NOT_SUPPORTED == (HTTPResponse::HTTPStatus)e.code())
				sendErrorResponse(*response, (HTTPResponse::HTTPStatus)e.code());
			else sendErrorResponse(*response, (HTTPResponse::HTTPStatus)e.code());
			throw e;
		}
	}
	catch (...) {
		DEBUGPOINT("EXCEPTION: Here\n");
		sendErrorResponse(*response, HTTPResponse::HTTP_BAD_REQUEST);
		throw;
	}
	return ;
}


/* This is the event driven equivalent of run method.
 * This method is reentrant.
 * The socket connection is expected to be non-blocking,
 * such that when there is no data to be read (EWOULDBLOCK/EAGAIN)
 * this function will return to the caller. whenever data reading is not
 * complete and the socket fd would block.
 * The caller is expected to call this function agian, when the 
 * socket fd becomes readable. */
void EVHTTPRequestProcessor::procHTTPReq(EVHTTPProcessingState *reqProcState)
{
	std::string server = _pParams->getSoftwareVersion();
	EVServerSession * session = NULL;
	if (_stopped) return ;

	EVHTTPServerResponseImpl *response = 0;
	EVHTTPServerRequestImpl *request = 0;

	try {
		Poco::FastMutex::ScopedLock lock(_mutex);
		session = reqProcState->getSession();
		if (!session) {
			session = new EVServerSession(socket(), _pParams);
			session->setServer(reqProcState->getServer());
			reqProcState->setSession(session);
		}
		/* To prevent Poco library from closing the socket. */
		session->setSockFdForReuse(true);

	} catch (std::exception e) {
		DEBUGPOINT("EXCEPTION: Here %s for %d\n", e.what(), socket().impl()->sockfd());
		throw;
	}

	request = reqProcState->getRequest();
	response = reqProcState->getResponse();
	try {
		if (!response) {
			response = new EVHTTPServerResponseImpl(*session);
			response->setMemoryStream(reqProcState->getResMemStream());
			reqProcState->setResponse(response);
		}
	} catch (...) {
		DEBUGPOINT("EXCEPTION: Here %p\n", reqProcState->getResponse());
		throw;
	}

	try {
		if (!request) {
			request = new EVHTTPServerRequestImpl(*response, *session, _pParams);
			request->setClientAddress(reqProcState->clientAddress());
			request->setServerAddress(reqProcState->serverAddress());
			reqProcState->setRequest(request);
		}
	} catch (...) {
		DEBUGPOINT("EXCEPTION: Here %p\n", reqProcState->getRequest());
		throw;
	}

	try {
		Poco::FastMutex::ScopedLock lock(_mutex);

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
		if (MESSAGE_COMPLETE > reqProcState->getState()) {
			/* TBD: 
			 * Pass the state to reading process, in order to retain 
			 * partially read name or value within the reading process.
			 * */
			int ret = reqProcState->continueRead();
			if (ret < 0) {
				DEBUGPOINT("EXCEPTION: Here\n");
				sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
				throw NetException("Badly formed HTTP Request");
				return ;
			}
			reqProcState->setState(ret);
			if (HEADER_READ_COMPLETE <= reqProcState->getState()) {
				switch (request->getReqType()) {
					case HTTP_HEADER_ONLY:
					case HTTP_FIXED_LENGTH:
					case HTTP_CHUNKED:
					case HTTP_MULTI_PART:
						break;
					case HTTP_MESSAGE_TILL_EOF:
					case HTTP_INVALID_TYPE:
					default:
						DEBUGPOINT("EXCEPTION: Here\n");
						throw NetException("Unsupported HTTP Request type");
						return;
				}

				if ((request->getVersion().compare("HTTP/1.1"))) {
					//sendErrorResponse(*session, *response, HTTPResponse::HTTP_VERSION_NOT_SUPPORTED);
					DEBUGPOINT("EXCEPTION: Here\n");
					throw Poco::Exception("Unsupported HTTP Version", HTTPResponse::HTTP_VERSION_NOT_SUPPORTED);
					return ;
				}

				if (!request->continueProcessed()) {
					Poco::Timestamp now;
					response->setDate(now);
					response->setVersion(request->getVersion());
					response->setKeepAlive(_pParams->getKeepAlive() && request->getKeepAlive());
					if (!server.empty())
						response->set("Server", server);

					if (request->getExpectContinue() && response->getStatus() == HTTPResponse::HTTP_OK) {
						//DEBUGPOINT("RESPONDING TO CONTINUE EXPECTATION\n");
						response->sendContinue();
					}
					request->setContinueProcessed();
				}
			}

			if (MESSAGE_COMPLETE > reqProcState->getState()) {
				return ;
			}

		}

		try
		{
			/* The use case being solved here is:
			 * The server reads complete HTTP request and then starts processing the request
			 * EVHTTPProcessingState is one per request.
			 * The request is processed once if there are further data requirements from
			 * upstream sockets those events will trigger handling of requests againa and
			 * again until complete processing of request.
			 * */
			EVHTTPRequestHandler * pHandler = reqProcState->getRequestHandler();
			if (!pHandler) {
				try {
					pHandler = _pFactory->createRequestHandler(*request);
					reqProcState->setRequestHandler(pHandler);
					pHandler->setServer(reqProcState->getServer());
					pHandler->setAccSockfd(socket().impl()->sockfd());
					pHandler->setAcceptedSocket(getAcceptedSocket());
					pHandler->setHTTPRequest(request);
					pHandler->setHTTPResponse(response);

					Poco::Timestamp now;
					response->setDate(now);
					response->setVersion(request->getVersion());
					response->setKeepAlive(_pParams->getKeepAlive() && request->getKeepAlive());
					if (!server.empty())
						response->set("Server", server);

					if (pHandler) {
						int ret = EVHTTPRequestHandler::PROCESSING;
						ret = pHandler->handleRequestSurrogateInitial();
						if (ret<0) ret = EVHTTPRequestHandler::PROCESSING_ERROR;
						switch (ret) {
							case EVHTTPRequestHandler::PROCESSING:
								reqProcState->setState(REQUEST_PROCESSING);
								break;
							case EVHTTPRequestHandler::PROCESSING_COMPLETE:
							case EVHTTPRequestHandler::PROCESSING_ERROR:
							default:
								reqProcState->setState(PROCESS_COMPLETE);
								break;
						}
					}
					else sendErrorResponse(*session, *response, HTTPResponse::HTTP_NOT_IMPLEMENTED);
				}
				catch (Exception e) {
					DEBUGPOINT("EXCEPTION: Here\n");
					throw e;
				}
				catch (std::exception e) {
					DEBUGPOINT("EXCEPTION: Here\n");
					char msg[100] = {0};
					sprintf(msg, "%s:%d UNKNOWN EXCEPTION",__FILE__, __LINE__);
					throw Exception(msg);
				}
			}
			else {
				if (reqProcState->getUpstreamEventQ() &&
						!queue_empty(reqProcState->getUpstreamEventQ())) {
					void * elem = dequeue(reqProcState->getUpstreamEventQ());
					bool processing_complete = false;
					while (!processing_complete && elem) {
						/* Process upstream events here. */
						std::unique_ptr<EVUpstreamEventNotification> usN((EVUpstreamEventNotification*)elem);
						try {
							pHandler->setState(usN->getCBEVIDNum());
							pHandler->setUNotification(usN.get());
							{
								int ret = EVHTTPRequestHandler::PROCESSING;
								ret = pHandler->handleRequestSurrogate();
								if (ret<0) ret = EVHTTPRequestHandler::PROCESSING_ERROR;
								switch (ret) {
									case EVHTTPRequestHandler::PROCESSING:
										reqProcState->setState(REQUEST_PROCESSING);
										break;
									case EVHTTPRequestHandler::PROCESSING_COMPLETE:
									case EVHTTPRequestHandler::PROCESSING_ERROR:
									default:
										processing_complete = true;
										reqProcState->setState(PROCESS_COMPLETE);
										break;
								}
							}
						}
						catch (Exception e) {
							DEBUGPOINT("EXCEPTION: Here\n");
							throw e;
						}
						catch (std::exception e) {
							DEBUGPOINT("EXCEPTION: Here\n");
							char msg[100] = {0};
							sprintf(msg, "%s:%d UNKNOWN EXCEPTION",__FILE__, __LINE__);
							throw Exception(msg);
						}
						//elem = NULL;
						elem = dequeue(reqProcState->getUpstreamEventQ());
						//if (elem) DEBUGPOINT("Found additional queued event\n");
					}
				}
				session->setKeepAlive(_pParams->getKeepAlive() && response->getKeepAlive());
			}
		}
		catch (Poco::Exception& e)
		{
			if (!response->sent()) {
				try
				{
					DEBUGPOINT("EXCEPTION: Here\n");
					sendErrorResponse(*session, *response, HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
				}
				catch (...)
				{
				DEBUGPOINT("EXCEPTION: Here\n");
				}
			}
			DEBUGPOINT("EXCEPTION: Here\n");
			throw e;
		}
		catch (...) {
			DEBUGPOINT("EXCEPTION: Here\n");
			sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
			throw;
		}
	}
	catch (NoMessageException& e)
	{
		DEBUGPOINT("EXCEPTION: Here\n");
		sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (MessageException& e)
	{
		DEBUGPOINT("EXCEPTION: Here\n");
		sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
		throw e;
	}
	catch (Poco::Exception& e)
	{
		if (session->networkException())
		{
			DEBUGPOINT("EXCEPTION: Here\n");
			if (0 == e.code()) sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
			else if (HTTPResponse::HTTP_VERSION_NOT_SUPPORTED == e.code())
				sendErrorResponse("HTTP/1.0", *session, *response, (HTTPResponse::HTTPStatus)e.code());
			else sendErrorResponse(*session, *response, (HTTPResponse::HTTPStatus)e.code());
			session->networkException()->rethrow();
		}
		else { 
			DEBUGPOINT("EXCEPTION: Here %s %d\n", e.what(), e.code());
			if (0 == e.code()) sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
			else if (HTTPResponse::HTTP_VERSION_NOT_SUPPORTED == (HTTPResponse::HTTPStatus)e.code())
				sendErrorResponse("HTTP/1.0", *session, *response, (HTTPResponse::HTTPStatus)e.code());
			else sendErrorResponse(*session, *response, (HTTPResponse::HTTPStatus)e.code());
			throw e;
		}
	}
	catch (...) {
		DEBUGPOINT("EXCEPTION: Here\n");
		sendErrorResponse(*session, *response, HTTPResponse::HTTP_BAD_REQUEST);
		throw;
	}
	return ;
}

void EVHTTPRequestProcessor::run()
{
	if (_reqProcState->getMode() == 1) {
		EVCommandLineProcessingState *reqProcState = dynamic_cast<EVCommandLineProcessingState*>(_reqProcState);
		return procCLReq(reqProcState);
	}
	else {
		EVHTTPProcessingState *reqProcState = dynamic_cast<EVHTTPProcessingState*>(_reqProcState);
		return procHTTPReq(reqProcState);
	}
}

void EVHTTPRequestProcessor::sendErrorResponse(EVCLServerResponseImpl & response, HTTPResponse::HTTPStatus status)
{
	response.setReturnStatus(1);
}

void EVHTTPRequestProcessor::sendErrorResponse(std::string http_version, EVServerSession& session,
			EVHTTPServerResponseImpl & response, HTTPResponse::HTTPStatus status)
{
	response.setVersion(http_version);
	response.setStatusAndReason(status);
	response.setKeepAlive(false);
	response.send() << std::flush;
	session.getServer()->dataReadyForSend(session.socket().impl()->sockfd());
	session.setKeepAlive(false);
}

void EVHTTPRequestProcessor::sendErrorResponse(EVServerSession& session,
			EVHTTPServerResponseImpl & response, HTTPResponse::HTTPStatus status)
{
	response.setVersion(HTTPMessage::HTTP_1_1);
	response.setStatusAndReason(status);
	response.setKeepAlive(false);
	response.send() << std::flush;
	session.getServer()->dataReadyForSend(session.socket().impl()->sockfd());
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


} } // namespace Poco::evnet
