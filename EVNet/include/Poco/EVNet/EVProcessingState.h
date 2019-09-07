//
// EVProcessingState.h
//
// Library: EVProcessingState
// Package: EVNet
// Module:  EVProcessingState
//
// Basic definitions for the Poco EVNet library.
// This file must be the first file included by every other EVNet
// header file.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <chunked_memory_stream.h>
#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVServer.h"
#include "Poco/EVNet/EVConnectedStreamSocket.h"

#include <map>
#ifndef EVNet_EVProcessingState_INCLUDED
#define EVNet_EVProcessingState_INCLUDED

namespace Poco {
namespace EVNet {

class Net_API EVProcessingState
	// This class is used as a marker to hold state data of processing of a request in a connection.
	// In case of event driven model of processing, the processing of a request may have to be
	// suspended mulptiple times, while data is being fetched from sources (e.g. client)
	//
	// The processing of the request is coded in such a way, that all the intermediate data is held within
	// a derivation of this base class and the state is destroyed at the end of processing of the request.
{
public:
	typedef std::map<poco_socket_t,EVConnectedStreamSocket *> CSColMapType;

	EVProcessingState(EVServer * server);
	virtual int getState() = 0;
	virtual ~EVProcessingState();
	virtual void setReqMemStream(chunked_memory_stream *memory_stream) = 0;
	virtual void setResMemStream(chunked_memory_stream *memory_stream) = 0;
	EVServer* getServer();
	void setNewDataNotProcessed();
	void setNewDataProcessed();
	bool newDataProcessed();
	void noMoreDataNecessary();
	void moreDataNecessary();
	bool needMoreData();
	EVConnectedStreamSocket * getEVConnSock(int fd);
	void setEVConnSock(EVConnectedStreamSocket * cs);

private:
	EVServer*		_server;
	int				_no_new_data;
	int				_need_more_data;
	CSColMapType	_cssMap;
};

inline EVProcessingState::EVProcessingState(EVServer * server):_server(server), _no_new_data(0), _need_more_data(0) { }
inline EVProcessingState::~EVProcessingState() { }
inline EVServer* EVProcessingState::getServer() { return _server; }
inline void EVProcessingState::setNewDataNotProcessed() { _no_new_data = 1; }
inline void EVProcessingState::setNewDataProcessed() { _no_new_data = 0; }
inline bool EVProcessingState::newDataProcessed() { return (_no_new_data == 0); }
inline void EVProcessingState::noMoreDataNecessary() { _need_more_data = 0; }
inline void EVProcessingState::moreDataNecessary() { _need_more_data = 1; }
inline bool EVProcessingState::needMoreData() { return (_need_more_data != 0); }
inline EVConnectedStreamSocket * EVProcessingState::getEVConnSock(int fd) { return _cssMap[fd]; }
inline void EVProcessingState::setEVConnSock(EVConnectedStreamSocket * cs) { _cssMap[cs->getSockfd()] = cs; }

}
} // End namespace Poco::EVNet





#endif
