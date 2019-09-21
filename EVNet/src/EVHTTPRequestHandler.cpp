//
// EVHTTPRequestHandler.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//
//


#include "Poco/EVNet/EVHTTPRequestHandler.h"


namespace Poco {
namespace EVNet {


EVHTTPRequestHandler::EVHTTPRequestHandler():
	_state(INITIAL)
{
}


EVHTTPRequestHandler::~EVHTTPRequestHandler()
{
    for ( SRColMapType::iterator it = _srColl.begin(); it != _srColl.end(); ++it ) {
        delete it->second;
    }
    _srColl.clear();
}

int EVHTTPRequestHandler::getState()
{
	return _state;
}

void EVHTTPRequestHandler::setState(int state)
{
	_state = state;
}

long EVHTTPRequestHandler::makeNewSocketConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;
	//int * cb_evid_num_ptr = new int;
	//*cb_evid_num_ptr = cb_ev_id_num;
	sr_num = server.submitRequestForConnection(cb_evid_num, getAccSockfd(), addr, css);
	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	//_srColl[sr_num] = cb_evid_num_ptr;
	return sr_num;
}

int EVHTTPRequestHandler::handleRequestSurrogate()
{
	Poco::EVNet::EVUpstreamEventNotification &usN = getUNotification();
	return 0;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;
	//int * cb_evid_num_ptr = new int;
	//*cb_evid_num_ptr = cb_ev_id_num;
	sr_num = server.submitRequestForConnection(cb_evid_num, getAccSockfd(), addr, css);
	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	//_srColl[sr_num] = cb_evid_num_ptr;
	return sr_num;
}

} } // namespace Poco::EVNet
