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

namespace Poco {
	namespace EVNet {
		enum {
			HEADER_NOT_READ = 0,
			HEADER_READ_IN_PROGRESS,
			HEADER_READ_COMPLETE,
			BODY_READ_IN_PROGRESS,
			READY_FOR_PROCESSING,
			PROCESS_COMPLETE,
			SERVER_STOPPED
		};
	}
}


#include "Poco/Foundation.h"


#endif
