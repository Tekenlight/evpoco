#
# Makefile
#
# Makefile for Poco EVHTTPSFormServer
#

include $(POCO_BASE)/build/rules/global

objects = EVHTTPSFormServer

target         = EVHTTPSFormServer
target_version = 1
target_libs    = PocoNetSSL PocoCrypto PocoEVNet PocoNet PocoUtil PocoJSON PocoXML PocoFoundation 

include $(POCO_BASE)/build/rules/exec

ifdef POCO_UNBUNDLED
        SYSLIBS += -lz -lpcre -lexpat
endif
