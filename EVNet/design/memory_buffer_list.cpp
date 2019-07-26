#include <stdlib.h>
#include <memory_buffer_list.h>


memory_buffer_list::node::node(): _next(0),_buffer(0),_size(0)
{
}

memory_buffer_list::node * memory_buffer_list::node::get_next()
{
	node *next = 0;
	next = (node*)atomic_load(&_next);
	return next;
}

void memory_buffer_list::node::set_buffer(void * buffer, size_t size)
{
	_buffer = buffer;
	_size = size;
}

void memory_buffer_list::node::set_next(node * np)
{
	atomic_store(&_next,(uintptr_t)np);
}

size_t memory_buffer_list::node::get_buffer_len()
{
	return _size;
}

void * memory_buffer_list::node::get_buffer()
{
	return _buffer;
}


memory_buffer_list::node::~node()
{
#ifndef NEVER
	free(_buffer);
	_buffer = 0;
#endif
	_size = 0;
	_next = 0;
}

memory_buffer_list::memory_buffer_list():_head(0),_tail(0)
{
}

memory_buffer_list::node * memory_buffer_list::get_head()
{
	node * head;
	head = (node*)atomic_load(&_head);
	return head;
}

memory_buffer_list::node * memory_buffer_list::get_next(node * ptr)
{
	return ptr->get_next();
}

memory_buffer_list::node * memory_buffer_list::get_tail()
{
	node * tail;
	tail = (node*)atomic_load(&_tail);
	return tail;
}

void memory_buffer_list::add_node(void * buffer, size_t size)
{
	node * np = new node();
	uintptr_t unp = (uintptr_t)np;
	node * old_tail = 0;
	np->set_buffer(buffer,size);
	np->set_next(0);
	old_tail = (node*)atomic_exchange(&_tail,(uintptr_t)np);
	/* For a brief period of time,
	 * 1. When the new tail node is being added there can be a discontinuity in the list.
	 * 2. Head can become null temporarily when the first record is being added.
	 * */
	if (old_tail) {
		old_tail->set_next(np);
	}
	else {
		atomic_exchange(&_head , _tail);
	}

	return;
}

memory_buffer_list::node * memory_buffer_list::pop_head()
{
	node * hp = 0;
	node * tail = (node*)atomic_load(&_tail);
	node * next = 0;
	/* This is a variation from the generic queue implementation,
	 * because
	 * 1. Generic queue assumes concurrent threads doing push and pop arbitrarily.
	 * 2. This queue provides for ony 2 threads concurrently acting
	 *    one only either reading or popping and another only pushing.
	 * Thus once we know that tail is not null, we can assume that
	 * no other thread will make it null.
	 * */
	if (tail) {
		/* Since there is tail, the list is not empty
		 * head can become null temporarily. we have to
		 * wait for head to become available. And again
		 * once it is available, no other thread will pop it out
		 * therefore no need for marking the head etc.
		 * */
		hp = (node*)atomic_load(&_head);
		while (!hp) { EV_YIELD(); hp = (node*)atomic_load(&_head); }
		//EV_DBGP(" hp = [%p]\n",hp);
		next = get_next(hp);
		if (!next) {
			bool flg = false;
			uintptr_t newh = (uintptr_t)hp;
			flg = atomic_compare_exchange_strong(&_tail,&newh,0);
			if (!flg) {
				// The case when one thread popped out the single node, also the head
				// and the other thread added concurrently
				do {
					EV_YIELD();
					next = get_next(hp);
				} while (!next);
			}
		}
		{
			uintptr_t h = (uintptr_t)hp;
			/* It is quite possible that by the time we want to set the head
			 * the value of _head could have changed, due to the fact that
			 * we set tail to 0 above in the compare exchange operation.
			 * The add_node method thought that the queue is empty and
			 * set a new value of _head.
			 * However if it happens to have not changed fro what was found
			 * initially here, we should change it to the next pointer in
			 * the chain.
			 * */
			atomic_compare_exchange_strong(&_head,&h,(uintptr_t)next);
		}
	}
	return hp;
}

memory_buffer_list::~memory_buffer_list()
{
	node * p = 0, *q = 0;
	p = (node*)atomic_load(&_head);
	while (p != 0) {
		q = p->get_next();
		delete p;
		p = q;
	}
}



#ifdef NEVER

struct test_inp {
	memory_buffer_list * buf_list;
	long no;
};

void * producer(void * inp)
{
	long i = 0L, n = 0L;
	struct test_inp * inp_ptr = NULL;
	inp_ptr = (struct test_inp *)inp;

	n = inp_ptr->no;

	for (i=0; i < n; i++) {
		inp_ptr->buf_list->add_node((void*)i, 100);
		//printf("Added %d th\n",i);
	}

	return NULL;
}

void * consumer(void * inp)
{
	memory_buffer_list::node * np = 0;
	long i = 0L, n = 0L, j= 0L;
	struct test_inp * inp_ptr = NULL;
	inp_ptr = (struct test_inp *)inp;
	n = inp_ptr->no;

	while (i < n) {
		np = inp_ptr->buf_list->pop_head();
		if (np) {
			//printf("Got j=%ld, n=%ld\n",(long)np->get_buffer(), n);

			// This condition is a test case, which ensures the 
			// sequential nature of the queue.
			if (i != (long)np->get_buffer()) exit(1);
			i++;
			delete np;
		}
	}
	return NULL;
}

int main(int argc, char * argv[])
{
	struct test_inp inp;
	pthread_t t1, t2;
	void * retptr = NULL;

	inp.no = atol(argv[1]);
	inp.buf_list = new memory_buffer_list();

	pthread_create(&t1, NULL, producer, &inp);
	pthread_create(&t2, NULL, consumer, &inp);

	pthread_join(t1, &retptr);
	pthread_join(t2, &retptr);
	/*
	producer(&inp);
	consumer(&inp);
	*/

	delete inp.buf_list;

	return 0;
}

#endif
