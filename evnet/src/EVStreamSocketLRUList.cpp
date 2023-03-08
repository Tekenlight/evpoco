//
// EVStreamSocketLRUList.cpp
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include "Poco/evnet/EVStreamSocketLRUList.h"

namespace Poco{ namespace evnet {

EVStreamSocketLRUList::EVStreamSocketLRUList(EVAcceptedStreamSocket* f,EVAcceptedStreamSocket* l):
	firstPtr(f),lastPtr(l)
{
}
EVStreamSocketLRUList::~EVStreamSocketLRUList()
{
}

EVAcceptedStreamSocket* EVStreamSocketLRUList::add(EVAcceptedStreamSocket* elem)
{
	EVAcceptedStreamSocket* temp = 0;
	temp = firstPtr;
	firstPtr = elem;
	firstPtr->setPrevPtr(0);
	firstPtr->setNextPtr(temp);
	if (!firstPtr->getNextPtr()) lastPtr = firstPtr;
	else (firstPtr->getNextPtr())->setPrevPtr(firstPtr);

	return elem;
}
EVAcceptedStreamSocket* EVStreamSocketLRUList::move(EVAcceptedStreamSocket* elem)
{
	if (firstPtr == elem) return elem;;
	(elem->getPrevPtr())->setNextPtr(elem->getNextPtr());
	if (lastPtr != elem) (elem->getNextPtr())->setPrevPtr(elem->getPrevPtr());
	else lastPtr = elem->getPrevPtr();
	elem->setPrevPtr(0);
	elem->setNextPtr(0);
	add(elem);

	return elem;
}
EVAcceptedStreamSocket* EVStreamSocketLRUList::removeFirst()
{
	auto ptr = firstPtr;
	if (firstPtr) firstPtr = firstPtr->getNextPtr();
	if (firstPtr) firstPtr->setPrevPtr(0);
	if (!firstPtr) lastPtr = 0;
	return ptr;
}
EVAcceptedStreamSocket* EVStreamSocketLRUList::removeLast()
{
	auto ptr = lastPtr;
	if (lastPtr) lastPtr = lastPtr->getPrevPtr();
	if (lastPtr) lastPtr->setNextPtr(0);
	if (!lastPtr) firstPtr = 0;
	return ptr;
}
EVAcceptedStreamSocket* EVStreamSocketLRUList::remove(EVAcceptedStreamSocket* elem)
{
	if (firstPtr == elem) removeFirst();
	else if (lastPtr == elem) removeLast();
	else {
		move(elem);
		removeFirst();
	}
	return elem;
}
void EVStreamSocketLRUList::debugPrint(const char* file, const int line, const void* tp)
{
	printf("[%s:%d:%p] {\n",file,line,tp);
	for (auto ptr = firstPtr; ptr ; ptr=ptr->getNextPtr()) {
		printf("\t[%s:%d:%p] [Socket = [%d] Last update time = [%ld]]\n",
				file,line,tp, ptr->getSockfd(),ptr->getTimeOfLastUse());
	}
	printf("[%s:%d:%p] }\n",file,line,tp);
}

} } // end namespace poco::evnet
