#include <ev_rwlock_struct.h>
#include <ev_rwlock.h>

static struct ev_rwlock_s sg_stmt_lock;
static struct ev_rwlock_s sg_m_o_m_lock;
static struct ev_rwlock_s sg_tmm_lock;
static atomic_int sg_lock_init_done = 0;

void init_locks_if_not_done()
{
	int l_i_d = 0;
	l_i_d = atomic_load(&sg_lock_init_done);
	if (l_i_d == 0) {
		if (atomic_compare_exchange_strong(&sg_lock_init_done, &l_i_d, 1)) {
			EV_RW_LOCK_S_INIT(sg_stmt_lock);
			EV_RW_LOCK_S_INIT(sg_m_o_m_lock);
			EV_RW_LOCK_S_INIT(sg_tmm_lock);
		}
	}
	return;
}

void sg_stmt_lock_wr_lock(int l)
{
	if (l) ev_rwlock_wrlock(&sg_stmt_lock);
	else ev_rwlock_wrunlock(&sg_stmt_lock);

	return;
}

void sg_stmt_lock_rd_lock(int l)
{
	if (l) ev_rwlock_rdlock(&sg_stmt_lock);
	else ev_rwlock_rdunlock(&sg_stmt_lock);

	return;
}

void sg_m_o_m_lock_wr_lock(int l)
{
	if (l) ev_rwlock_wrlock(&sg_m_o_m_lock);
	else ev_rwlock_wrunlock(&sg_m_o_m_lock);

	return;
}

void sg_m_o_m_lock_rd_lock(int l)
{
	if (l) ev_rwlock_rdlock(&sg_m_o_m_lock);
	else ev_rwlock_rdunlock(&sg_m_o_m_lock);

	return;
}

void sg_tmm_lock_wr_lock(int l)
{
	if (l) ev_rwlock_wrlock(&sg_tmm_lock);
	else ev_rwlock_wrunlock(&sg_tmm_lock);

	return;
}

void sg_tmm_lock_rd_lock(int l)
{
	if (l) ev_rwlock_rdlock(&sg_tmm_lock);
	else ev_rwlock_rdunlock(&sg_tmm_lock);

	return;
}

