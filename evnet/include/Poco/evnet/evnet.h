//
// evnet.h
//
// Library: evnet
// Package: NetCore
// Module:  evnet
//
// Basic definitions for the Poco evnet library.
// This file must be the first file included by every other evnet
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
#include <libgen.h>

/*
char** strs = backtrace_symbols(callstack, frames);
for (i = 0; i < frames; ++i) {
	printf("%s\n", strs[i]);
}
free(strs);
*/

#ifdef STACK_TRACE
#undef STACK_TRACE
#endif
#include <execinfo.h>
#define STACK_TRACE() {\
	void* callstack[128]; \
	int i, frames = backtrace(callstack, 128); \
	backtrace_symbols_fd(callstack, frames, STDERR_FILENO); \
}

#ifdef __APPLE__
#include "TargetConditionals.h"

#if TARGET_OS_IPHONE && TARGET_IPHONE_SIMULATOR

#if defined TARGET_OS_ONLY_IPHONE_SIMULATOR
#undef TARGET_OS_ONLY_IPHONE_SIMULATOR
#endif
#define TARGET_OS_ONLY_IPHONE_SIMULATOR 1

#elif TARGET_OS_IPHONE

#if defined TARGET_OS_UNION_IPHONE
#undef TARGET_OS_UNION_IPHONE
#endif
#define TARGET_OS_UNION_IPHONE 1

#else

#if defined TARGET_OS_OSX
#undef TARGET_OS_OSX
#endif
#define TARGET_OS_OSX 1

#endif

#endif

#ifdef EV_YIELD
#undef EV_YIELD
#endif

#ifdef TARGET_OS_OSX
#define EV_YIELD() pthread_yield_np()
#elif defined _WIN32
#define EV_YIELD() sleep(0);
#else
#define EV_YIELD()  pthread_yield();
#endif

#ifdef __linux__
#define DEBUGPOINT(...) { \
	char filename[512]; \
	char *fpath; \
	fflush(stdout); \
	strcpy(filename, __FILE__); \
    fpath = basename(filename); printf("[%p][%s:%d] Reached:",(void*)pthread_self(), fpath, __LINE__); \
    printf(__VA_ARGS__);fflush(stdout); fflush(stdout); \
}
#else
#define DEBUGPOINT(...) { \
	char fpath[256]; \
	fflush(stdout); \
    basename_r(__FILE__,fpath); printf("[%p][%s:%d] Reached:",(void*)pthread_self(), fpath, __LINE__); \
    printf(__VA_ARGS__);fflush(stdout); fflush(stdout); \
}
#endif

#ifndef ULLONG_MAX
#define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif


#ifdef __linux__
#define AI_DEFAULT AI_V4MAPPED | AI_ADDRCONFIG
#endif

/*
#define DEBUGPOINT(s) {\
	printf("%s:%d:%p %s\n",__FILE__,__LINE__,pthread_self(),s); \
}
*/

namespace Poco {
namespace evnet {

#define EVHTTPP_TRANSFER_ENCODING "transfer-encoding"


	typedef enum {
		HTTP_INVALID_TYPE,
		HTTP_HEADER_ONLY,
		HTTP_FIXED_LENGTH,
		HTTP_MULTI_PART,
		HTTP_CHUNKED,
		HTTP_MESSAGE_TILL_EOF
	} HTTP_REQ_TYPE_ENUM;

	enum httpMsgProcState {
		 HEADER_NOT_READ = 0
		,STATUS_LINE_READ
		,HEADER_READ_COMPLETE
		,POST_HEADER_READ_COMPLETE
		,BODY_POSITION_MARKED
		,PART_COMPLETE
		,NEW_CHUNK
		,CHUNK_HEADER_COMPLETE
		,CHUNK_COMPLETE
		,MESSAGE_COMPLETE
		,REQUEST_PROCESSING
		,PROCESS_COMPLETE
	};

	enum reqProcSubState {
		 READ_START = 0
		,METHOD_READ_IN_PROGRESS
		,METHOD_READ_PART_ONE_COMPLETE
		,URI_READ_IN_PROGRESS
		,URI_READ_PART_ONE_COMPLETE
		,VERSION_READ_IN_PROGRESS
		,VERSION_READ_PART_ONE_COMPLETE
		,VERSION_READ_COMPLETE
		,NAME_READ_IN_PROGRESS
		,NAME_READ_PART_ONE_COMPLETE
		,NAME_READ_PART_TWO_COMPLETE
		,VALUE_READ_IN_PROGRESS
		,VALUE_READ_PART_ONE_COMPLETE
		,VALUE_READ_PART_TWO_COMPLETE
		,VALUE_READ_PART_THREE_COMPLETE
		,VALUE_READ_PART_FOUR_COMPLETE
		,VALUE_READ_PART_FIVE_COMPLETE
		,VALUE_READ_PART_SIX_COMPLETE
		,VALUE_READ_PART_SEVEN_COMPLETE
		,VALUE_READ_PART_EIGHT_COMPLETE
		,VALUE_READ_PART_NINE_COMPLETE
		,BODY_BEGINING_MARKED
	};
}
}


#include "Poco/Foundation.h"


#endif
