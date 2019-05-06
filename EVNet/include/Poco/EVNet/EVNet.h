//
// EVNet.h
//
// Library: EVNet
// Package: NetCore
// Module:  EVNet
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


#ifndef EVNet_EVNet_INCLUDED
#define EVNet_EVNet_INCLUDED

#include <pthread.h>
#include <stdio.h>

#define DEBUGPOINT(...) { \
    printf("[%p][%s:%d] Reached:",(void*)pthread_self(),__FILE__,__LINE__); \
    printf(__VA_ARGS__);fflush(stdout); \
}

/*
#define DEBUGPOINT(s) {\
	printf("%s:%d:%p %s\n",__FILE__,__LINE__,pthread_self(),s); \
}
*/

namespace Poco {
	namespace EVNet {
		enum reqProcState {
			HEADER_NOT_READ = 0,
			STATUS_LINE_READ,
			HEADER_READ_COMPLETE,
			BODY_READ_COMPLETE,
			PROCESS_COMPLETE,
			SERVER_STOPPED
		};

		enum reqProcSubState {
			READ_START = 0,
			METHOD_READ_IN_PROGRESS,
			METHOD_READ_PART_ONE_COMPLETE,
			URI_READ_IN_PROGRESS,
			URI_READ_PART_ONE_COMPLETE,
			VERSION_READ_IN_PROGRESS,
			VERSION_READ_PART_ONE_COMPLETE,
			VERSION_READ_COMPLETE,
			NAME_READ_IN_PROGRESS,
			NAME_READ_PART_ONE_COMPLETE,
			NAME_READ_PART_TWO_COMPLETE,
			VALUE_READ_IN_PROGRESS,
			VALUE_READ_PART_ONE_COMPLETE,
			VALUE_READ_PART_TWO_COMPLETE,
			VALUE_READ_PART_THREE_COMPLETE,
			VALUE_READ_PART_FOUR_COMPLETE,
			VALUE_READ_PART_FIVE_COMPLETE,
			VALUE_READ_PART_SIX_COMPLETE,
			VALUE_READ_PART_SEVEN_COMPLETE,
			VALUE_READ_PART_EIGHT_COMPLETE,
			VALUE_READ_PART_NINE_COMPLETE
		};
	}
}


#include "Poco/Foundation.h"


#endif
