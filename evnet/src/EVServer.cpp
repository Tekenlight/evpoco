#include "Poco/evnet/EVServer.h"

namespace Poco {
namespace evnet {

EVServer::EVServer():_aborting(false),_lock(ev_rwlock_init())
{
}

EVServer::~EVServer()
{
	ev_rwlock_destroy(this->_lock);
}


}
}

