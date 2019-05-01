#
# Makefile
#
# Makefile for Poco EVNet
#

include $(POCO_BASE)/build/rules/global

SYSLIBS += -lev

objects = EVHTTPServer EVTCPServer EVHTTPServerConnection EVTCPServerNotification EVHTTPServerConnectionFactory \
			EVAcceptedStreamSocket EVHTTPRequestHandlerFactory EVTCPServerDispatcher EVStreamSocketLRUList \
			HTTPServerRequestImpl

target         = PocoEVNet
target_version = $(LIBVERSION)
target_libs    = 
target_libs    = PocoNet PocoUtil PocoFoundation 

include $(POCO_BASE)/build/rules/lib
