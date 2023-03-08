//
// EVHTTPServer.cpp
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPServer
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVHTTPServer.h"
#include "Poco/evnet/EVHTTPRequestProcessorFactory.h"


namespace Poco {
namespace evnet {


EVHTTPServer::EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, Poco::UInt16 portNumber, HTTPServerParams::Ptr pParams)
{
	_pTCPServer = new EVTCPServer(new EVHTTPRequestProcessorFactory(pParams, pFactory), portNumber, pParams);
	_pFactory = pFactory;
}

EVHTTPServer::EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, const ServerSocket& socket, HTTPServerParams::Ptr pParams)
{
	_pTCPServer = new EVTCPServer(new EVHTTPRequestProcessorFactory(pParams, pFactory), socket, pParams);
	_pFactory = pFactory;
}


EVHTTPServer::EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, Poco::ThreadPool& threadPool, const ServerSocket& socket, HTTPServerParams::Ptr pParams)
{
	_pTCPServer = new EVTCPServer(new EVHTTPRequestProcessorFactory(pParams, pFactory), threadPool, socket, pParams);
	_pFactory = pFactory;
}

EVHTTPServer::EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, int pipe_rd_fd, int pipe_wr_fd, HTTPServerParams::Ptr pParams)
{
	_pTCPServer = new EVTCPServer(new EVHTTPRequestProcessorFactory(pParams, pFactory), pipe_rd_fd, pipe_wr_fd, pParams);
	_pFactory = pFactory;
}


EVHTTPServer::~EVHTTPServer()
{
	delete _pTCPServer;
}

void EVHTTPServer::setConfigNames(std::string serverPrefix, std::string numThreads, std::string receiveTimeOut,
			std::string numConnections, std::string useIpv6ForConn)
{
	_pTCPServer->setConfigNames(serverPrefix, numThreads, receiveTimeOut, numConnections, useIpv6ForConn);
	return;
}

void EVHTTPServer::setServerPrefix(std::string serverPrefix)
{
	_pTCPServer->setServerPrefix(serverPrefix);
	return;
}

	void setServerPrefix(std::string serverPrefix);
void EVHTTPServer::stopAll(bool abortCurrent)
{
	_pTCPServer->stop();
	_pFactory->stopServer(this, abortCurrent);
}

void EVHTTPServer::start()
{
	_pTCPServer->start();
	return;
}

void EVHTTPServer::stop()
{
	_pTCPServer->stop();
	return;
}

} } // namespace Poco::evnet
