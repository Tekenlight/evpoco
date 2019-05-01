//
// EVStreamSocketLRUList.h
//
// Library: EVNet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVAcceptedStreamSocket.h"

#ifndef POCO_EVNET_EVSTREAMSOCKETLRULIST_INCLUDED
#define POCO_EVNET_EVSTREAMSOCKETLRULIST_INCLUDED

namespace Poco{ namespace EVNet {


class Net_API EVStreamSocketLRUList
{
public:
	EVStreamSocketLRUList(EVAcceptedStreamSocket* f,EVAcceptedStreamSocket* l);
	~EVStreamSocketLRUList();

	EVAcceptedStreamSocket* add(EVAcceptedStreamSocket* elem);
	EVAcceptedStreamSocket* move(EVAcceptedStreamSocket* elem);
	EVAcceptedStreamSocket* removeFirst();
	EVAcceptedStreamSocket* removeLast();
	EVAcceptedStreamSocket* remove(EVAcceptedStreamSocket* elem);
	EVAcceptedStreamSocket* getLast();
	void debugPrint(const char* file, const int line, const void* tp);

private:
	EVAcceptedStreamSocket*	firstPtr;
	EVAcceptedStreamSocket*	lastPtr;
};

inline EVAcceptedStreamSocket * EVStreamSocketLRUList::getLast()
{
	return lastPtr;
}


} } // end namespace poco::evnet




#endif

