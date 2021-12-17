#include <iostream>
#include <algorithm>
#include <map>
#include <dlfcn.h>
#include <ev_rwlock_struct.h>
#include <ev_rwlock.h>


static std::map<std::string, void*> sg_dlls;
static atomic_int sg_lock_init_done = 0;
static struct ev_rwlock_s sg_dlls_lock;

extern "C" void init_so_tracker_lock();
void init_so_tracker_lock()
{
	EV_RW_LOCK_S_INIT(sg_dlls_lock);
	sg_lock_init_done = 1;
}

/*
 * This function caches loaded Shared objects in a static hashmap
 * This is called from within lua code.
 *
 * When SOs are loaded in lua they get closed as well upon lua state closure.
 * This leads to some of the function pointers and virtual methods becoming stale
 * in cached objects.
 *
 * This function is essentially used to open the same SO once again, and thus increase
 * the open count by 1, which leads to dlclose not closing the SO from memory.
 *
 */
extern "C" void * pin_loaded_so(const char * libname);
void * pin_loaded_so(const char * libname)
{
	void * lib = NULL;
	std::string name(libname);
	ev_rwlock_rdlock(&sg_dlls_lock);
	auto it = sg_dlls.find(name);
	if (sg_dlls.end() == it) {
		ev_rwlock_rdunlock(&sg_dlls_lock);
		ev_rwlock_wrlock(&sg_dlls_lock);
		it = sg_dlls.find(name);
		if (sg_dlls.end() == it) {
			lib = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL);
			if (lib) {
				sg_dlls[name] = lib;
			}
		}
		else {
			lib = it->second;
		}
		ev_rwlock_wrunlock(&sg_dlls_lock);
		ev_rwlock_rdlock(&sg_dlls_lock);
	}
	else {
		lib = it->second;
	}
	ev_rwlock_rdunlock(&sg_dlls_lock);
	return lib;
}

