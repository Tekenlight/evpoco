#ifndef EVNet_EVServer_INCLUDED
#define EVNet_EVServer_INCLUDED

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libev.h>

#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/evnet/EVAcceptedSocket.h"

#include <ev_rwlock.h>

namespace Poco {
namespace evnet {

typedef void* (*generic_task_handler_t)(void*);
typedef void (*generic_task_handler_nr_t)(void*);

class Net_API EVServer {
public:
	EVServer();
	~EVServer();
	virtual void receivedDataConsumed(int fd)=0;
	virtual void errorInReceivedData(poco_socket_t fd, bool connInErr)=0;
	virtual void dataReadyForSend(int fd)=0;
	virtual long submitRequestForConnection(int cb_evid_num,
								EVAcceptedSocket *tn, Net::SocketAddress& addr, Net::StreamSocket & css, int timeout = -1)=0;
	virtual long submitRequestForPoll(int cb_evid_num, EVAcceptedSocket *tn,
										Net::StreamSocket& css, int poll_for, int managed = 1, int time_out = -1) = 0;
	virtual long submitRequestForHostResolution(int cb_evid_num,
											EVAcceptedSocket *tn, const char* domain_name, const char* serv_name)=0;
	virtual long submitRequestForClose(EVAcceptedSocket *tn, Net::StreamSocket& css)=0;
	virtual long submitRequestForSendData(EVAcceptedSocket *tn, Net::StreamSocket& css)=0;
	virtual long submitRequestForRecvData(int cb_evid_num, EVAcceptedSocket *tn, Net::StreamSocket& css, int timeout = -1)=0;
	virtual long submitRequestForTaskExecution(int cb_evid_num, EVAcceptedSocket *tn, generic_task_handler_t tf, void* input_data) = 0;
	virtual long submitRequestForTaskExecutionNR(generic_task_handler_nr_t tf, void* input_data) = 0;
	virtual long notifyOnFileOpen(int cb_evid_num, EVAcceptedSocket *tn, int fd) = 0;
	virtual long notifyOnFileRead(int cb_evid_num, EVAcceptedSocket *tn, int fd) = 0;
	virtual void redisLibevAttach(redisAsyncContext *ac) = 0;
	virtual long redistransceive(int cb_evid_num, EVAcceptedSocket *en, redisAsyncContext *ac, const char * messge) = 0;
	virtual long redisDisconnect(int cb_evid_num, EVAcceptedSocket *en, redisAsyncContext *ac) = 0;
	virtual long sendRawDataOnAccSocket(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& accss, void* data, size_t len) = 0;
	virtual long trackAsWebSocket(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& connss, const char * msg_handler) = 0;
	virtual long evTimer(int cb_evid_num, EVAcceptedSocket *en, int time_in_ms) = 0;
	virtual long shutdownWebSocket(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket &ss, int type) = 0;
	virtual long stopTakingRequests(int cb_evid_num) = 0;
	virtual long webSocketActive(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket &ss) = 0;
	virtual long asyncRunLuaScript(int cb_evid_num, EVAcceptedSocket *en, int argc, char * argv[], bool single_instance) = 0;
	virtual long stopTrackingConnSock(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& connss) = 0;
	bool aborting();
	void setAborting();

private:
	bool			_aborting;
	ev_rwlock_type	_lock;
};

inline bool EVServer::aborting()
{
	bool value = false;
	ev_rwlock_rdlock(this->_lock);
	value = _aborting;
	ev_rwlock_rdunlock(this->_lock);
	return value;
}

inline void EVServer::setAborting()
{
	if (_aborting) return;
	ev_rwlock_wrlock(this->_lock);
	_aborting = true;
	ev_rwlock_wrunlock(this->_lock);
}

}
}

#endif
