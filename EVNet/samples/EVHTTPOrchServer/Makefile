#
# Makefile
#
# Makefile for Poco EVHTTPOrchServer
#

include $(POCO_BASE)/build/rules/global

objects = EVHTTPOrchServer

target         = EVHTTPOrchServer
target_version = 1
target_libs    = PocoUtil PocoJSON PocoNet PocoXML PocoFoundation PocoEVNet

include $(POCO_BASE)/build/rules/exec

ifdef POCO_UNBUNDLED
        SYSLIBS += -lz -lpcre -lexpat
endif
