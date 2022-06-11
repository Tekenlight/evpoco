#include "Poco/evnet/EVServer.h"

namespace Poco {
namespace evnet {

EVServer::EVServer():_aborting(false), _lock(create_spin_lock())
{
}

EVServer::~EVServer()
{
	destroy_spin_lock(this->_lock);
}


}
}

