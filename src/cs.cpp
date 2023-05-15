/*

	TCP
	TCP是面向连接的，字节流协议，因此基于libuv的stream实现。
	libuv 对于 tcp 消息的处理，同样是基于 stream 的，步骤如下：

	server
	uv_tcp_init() 建立 tcp 句柄；
	uv_tcp_bind() 方法绑定ip；
	uv_listen() 方法监听，有新连接时，调用回调函数；
	uv_accept() 方法获取客户端套接字；
	uv_read_start() 方法读取客户端数据；
	uv_write() 方法向客户端发送数据；
	uv_close() 关闭套接字；

	client
	uv_tcp_init() 建立 tcp 句柄；
	uv_tcp_connect() 方法绑定ip；
	uv_write() 方法向服务器发送数据；
	uv_close() 关闭套接字；
*/

#include <uv.h> 
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> 
#include "cs.h"

const size_t udpmaxs = (1024 * 64 - 256);// 1024 * 32;// 1472;
sem_st* run_loop(uv_loop_t* loop, int r);

// 对齐字节
template<typename T> inline T alignUp(const T& val, T alignment)
{
	T r = (val + alignment - (T)1) & ~(alignment - (T)1);
	return r;
}
#if 1
// 默认16字节对齐
void* alloc_m(size_t size, size_t a)
{
	auto ns = alignUp(size, a);
	return ns > 0 ? malloc(ns) : nullptr;
}
template<class T>
T* new_obj(size_t n = 1)
{
	auto p = (T*)alloc_m(sizeof(T) * n);
	for (int i = 0; i < n; i++)
	{
		p[i] = {};
	}
	return p;
}

void free_m(void* p)
{
	if (p)
		free(p);
}
template<class T>
void free_obj(T*& p)
{
	if (p)
	{
		p->~T();
		free(p); p = 0;
	}
}
#endif
void free_sem(sem_st* p)
{
	if (p)
	{
		delete p;
	}
}

template<class T>
void o_close(T* p)
{
	if (p)
	{
		uv_close((uv_handle_t*)p, 0);
	}
}

base_uv::base_uv()
{
	int r = 0;
	loop = ac.new_obj<uv_loop_t>();
	uv_loop_init(loop);
	_async = ac.new_obj<uv_async_t>();
	_async->data = this;
	r = uv_async_init(loop, _async, async_cb);
}

base_uv::~base_uv()
{
	o_close(_async);
	if (loop)
	{
		uv_stop(loop);
		free_sem(sem);
	}
	ac.free_obj(loop);
}

void base_uv::send_data(const void* d, int size)
{

}
// 线程调用
void base_uv::send_datas()
{

}
void base_uv::async_cb(uv_async_t* handle)
{
	if (handle && handle->data)
	{
		auto p = (base_uv*)handle->data;
		if (p)
		{
			if (p->acb)
				p->acb();
			p->send_datas();
		}
	}
}

int canipv6(void)
{
	uv_interface_address_t* addr;
	int supported;
	int count;
	int i;

	if (uv_interface_addresses(&addr, &count))
		return 0;  /* Assume no IPv6 support on failure. */

	supported = 0;
	for (i = 0; supported == 0 && i < count; i += 1)
		supported = (AF_INET6 == addr[i].address.address6.sin6_family &&
			!addr[i].is_internal);

	uv_free_interface_addresses(addr, count);
	return supported;
}



client_cx::client_cx()
{
}

client_cx::~client_cx()
{
}

void client_cx::read_u(ssize_t nread, const uv_buf_t* buf)
{
	static std::string str;
	if (nread > 0)
	{
		if (rcb)
		{
			(*rcb)(this, buf->base, nread);
		}
		else
		{
			str.assign(buf->base, nread);
			printf("%p\t%s\n", stream, str.c_str());
		}
	}
	else {
		printf("客户端：%s\n", uv_strerror(nread));
	}

}

void client_cx::close_cb(uv_handle_t* handle)
{
	auto p = (client_cx*)handle->data;
	if (p)
	{
		delete p; handle->data = 0;
	}
}
void client_cx::c_after_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
	if (nread < 0)
	{
		// 客户端断开
		uv_close((uv_handle_t*)handle, close_cb);
	}
	auto p = (client_cx*)handle->data;
	if (p)
	{
		p->read_u(nread, buf);
	}
}
void client_cx::u_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	auto p = (client_cx*)handle->data;
	assert(p);
	//suggested_size = 1024 * 1024;
	if (p)
	{
		if (p->b.len < suggested_size)
		{
			p->ac.free_mem(p->b.base, p->b.len);
			p->ac.new_mem(p->b.base, suggested_size);
			p->b.len = suggested_size;
		}
		buf->base = p->b.base;
		buf->len = suggested_size;
	}
	else {
		static std::string abuf;
		if (abuf.size() < suggested_size)
		{
			abuf.resize(suggested_size);
		}
		buf->base = abuf.data();
		buf->len = suggested_size;
	}
}
void client_cx::accept_u(uv_stream_t* server)
{
	stream = ac.new_mem<uv_stream_t>(1);
	//ASSERT_NOT_NULL(stream);
	int r = uv_tcp_init(server->loop, (uv_tcp_t*)stream);
	assert(r == 0);
	/* associate server with stream */
	stream->data = this;
	r = uv_accept(server, stream);
	assert(r == 0);

	r = uv_read_start(stream, u_alloc, c_after_read);
	assert(r == 0);
}
//服务器
tcps_cx::tcps_cx()
{
	ptr = ac.new_obj<uv_tcp_t>();
	uv_tcp_init(loop, ptr);
	ptr->data = this;
}

tcps_cx::~tcps_cx()
{
	ac.free_obj(ptr);
}
struct saddr_t
{
	union {
		struct sockaddr_in addr;
		struct sockaddr_in6 addr6;
	}v = {};
};
saddr_t get_addr(int port, int ipv6, const char* ip)
{
	saddr_t a = {};
	int	r = ipv6 ? uv_ip6_addr(ip ? ip : "::1", port, &a.v.addr6) : uv_ip4_addr(ip ? ip : "127.0.0.1", port, &a.v.addr);
	return a;
}
void tcps_cx::bind(int port, int ipv6, const char* ip)
{
	int r;
	do
	{
		if (port < 1) break;
		auto addr = get_addr(port, ipv6, ip);
		auto p = (sockaddr*)&addr;
		uv_tcp_bind(ptr, p, 0);
		r = uv_listen((uv_stream_t*)ptr, SOMAXCONN, on_connection);
		if (r != 0)break;
		sem = run_loop(loop, r);
	} while (0);
}

void tcps_cx::wait()
{
	if (sem)
		sem->wait();
}


void tcps_cx::on_connection(uv_stream_t* server, int status)
{
	auto p = (tcps_cx*)server->data;
	int r;

	if (status != 0) {
		fprintf(stderr, "Connect error %s\n", uv_err_name(status));
	}
	assert(status == 0);
	auto pc = new client_cx();
	if (pc)
	{
		if (p->rcb)
			pc->rcb = &p->rcb;
		pc->accept_u(server);
		if (p->conn_cb)
			p->conn_cb(pc);
	}
}


tcpc_cx::tcpc_cx()
{
	//uvreq = ac.new_obj<uv_write_t>();
	acb = [=]() {
		if (rs)
		{
			uv_tcp_init(loop, cli);
			int r = uv_tcp_connect(ctp, cli, (const struct sockaddr*)paddr, on_connect1);
			printf("重连：%s\n", uv_strerror(r));
		}
	};
}

tcpc_cx::~tcpc_cx()
{
	o_close(_async);
	o_close(cli);
	if (loop)
	{
		uv_stop(loop);
		free_sem(sem);
	}
	//ac.free_obj(uvreq);
	ac.free_obj(paddr);
	ac.free_obj(ctp);
	ac.free_obj(cli);
	ac.free_obj(loop);
}
void tcpc_cx::on_connect1(uv_connect_t* req, int status)
{
	auto p = (tcpc_cx*)req->data;
	if (p)
		p->on_connect(req, status);
}
void tcpc_cx::reset_connect()
{
	if (_async)
	{
		uv_async_send(_async);
	}
}

void tcpc_cx::set_recv_cb(std::function<void(char* d, int len)> cb)
{
	rcb = cb;
}

void tcpc_cx::run()
{
	if (!sem)
		sem = run_loop(loop, 0);
}

void write_cb(uv_write_t* req, int status) {
	if (status) {
		fprintf(stderr, "Write error %s\n", uv_strerror(status));
	}
	auto p = (tcpc_cx*)req->handle->data;
	if (p && req->data) {
		auto pb = (int*)req->data;
		printf("free %p\n", pb);
		p->ac.free_mem((char*)pb, *pb);
	}
}
void tcpc_cx::send_datas()
{
	if (_data.size())
	{
		lk.lock();
		for (; _data.size();)
		{
			auto p = _data.front();
			if (p.base && p.len)
			{
				uv_buf_t buf = uv_buf_init((char*)p.base, (size_t)p.len);
				//uvreq->data = p.base - sizeof(int);
				/*			int r = uv_write(uvreq, (uv_stream_t*)cli, &buf, 1, write_cb);
							if (r != 0)
							{
								rs = 1;
								printf("%s\n", uv_strerror(r));
							}*/
				auto n = uv_try_write((uv_stream_t*)cli, &buf, 1);
				if (n < 0)
				{
					printf("%s\n", uv_strerror(n));
				}
			}
			_data.pop();
		}
		lk.unlock();
	}
}

void tcpc_cx::send_data(const void* d, int size)
{
	if (!d || size < 1 || rs != 0)return;
	lk.lock();
	buf_tx b = {};
	b.base = (char*)d;
	b.len = size;
	_data.push(b);
	lk.unlock();
	post();
}
void tcpc_cx::send_data_try(const void* d, int size)
{
	if (!d || size < 1 || rs != 0)return;
	lk.lock();
	buf_tx b = {};
	b.base = (char*)d;
	b.len = size;
	_data.push(b);
	lk.unlock();
}
void tcpc_cx::post()
{
	if (_async)
	{
		uv_async_send(_async);
	}
	else
	{
		send_datas();
	}
}
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	auto p = (tcpc_cx*)handle->data;
	if (p)
	{
		if (p->b.len < suggested_size)
		{
			p->ac.free_mem(p->b.base, p->b.len);
			p->ac.new_mem(p->b.base, suggested_size);
			p->b.len = suggested_size;
		}
		buf->base = p->b.base;
		buf->len = suggested_size;
	}
	else {
		static std::string abuf;
		if (abuf.size() < suggested_size)
		{
			abuf.resize(suggested_size);
		}
		buf->base = abuf.data();
		buf->len = suggested_size;
	}
}
void read_client_cb(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {

	auto p = (tcpc_cx*)client->data;
	if (!p) {
		return;
	}
	if (nread > 0)
	{
		p->rcb(buf->base, nread);
	}
	if (nread < 0) {
		if (nread != UV_EOF)
			fprintf(stderr, "Read error %s\n", uv_err_name(nread));
		uv_close((uv_handle_t*)client, NULL);
		// todo 重连？
		p->rs = 1;
	}

	//free_m(buf->base);
}

void tcpc_cx::on_connect(uv_connect_t* req, int status)
{
	if (status < 0)
	{
		uv_close((uv_handle_t*)req->handle, 0);
		rs = 1;
		fprintf(stderr, "Connection error %s\n", uv_strerror(status));
		return;
	}
	uv_read_start((uv_stream_t*)req->handle, alloc_buffer, read_client_cb);
	assert((uv_stream_t*)cli == req->handle);
	rs = 0;
	fprintf(stdout, "Connect ok\n");

}

int tcpc_cx::conntect(const char* ip, int port, int ipv6)
{
	int r;
	if (cli)
		ac.free_obj(cli);
	cli = ac.new_obj<uv_tcp_t>();
	cli->data = this;
	if (ctp)
		ac.free_obj(ctp);
	ctp = ac.new_obj<uv_connect_t>();
	ctp->data = this;

	uv_tcp_init(loop, cli);

	auto addr = ac.new_obj<saddr_t>(get_addr(port, ipv6, ip));
	paddr = (sockaddr*)addr;
	r = uv_tcp_connect(ctp, cli, (const struct sockaddr*)paddr, on_connect1);
	return r;
}



sem_st::sem_st()
{
	sem = (uv_sem_t*)alloc_m(sizeof(uv_sem_t));
	if (sem)
		uv_sem_init(sem, 0);
}

sem_st::~sem_st()
{
	join();
	if (sem)
	{
		uv_sem_destroy(sem);
		free_m(sem);
		sem = 0;
	}
}

void sem_st::post()
{
	if (sem)
		uv_sem_post(sem);
}

int sem_st::wait(int ms)
{
	uv_sem_wait(sem);
	return 0;
}
int sem_st::wait_try()
{
	return uv_sem_trywait(sem);
}

void sem_st::join()
{
	if (a.joinable())
		a.join();
}

sem_st* run_loop(uv_loop_t* loop, int r)
{
	sem_st* p = new sem_st();
	if (loop)
	{
		if (r != 0)
		{
			delete p; p = 0;
		}
		std::thread a([=] {
			{
				if (r == 0)
				{
					uv_run(loop, UV_RUN_DEFAULT);
				}
				uv_loop_close(loop);
				if (p)
					p->post();
			}
			});
		if (p)
		{
			p->a.swap(a);
		}
		else
		{
			a.detach();
		}
	}
	return p;
}



// 客户端 

udpc_cx::udpc_cx()
{
}
udpc_cx::~udpc_cx()
{
	o_close(cli);
	ac.free_obj(paddr);
	ac.free_obj(cli);
}

int udpc_cx::set_ip(const char* ip, int port, int ipv6)
{
	int r;
	if (!cli)
	{
		cli = ac.new_obj<uv_udp_t>();
		cli->data = this;
		uv_udp_init(loop, cli);
	}

	//auto addr = ac.new_obj<saddr_t>(get_addr(port, ipv6, ip));
	//paddr = (sockaddr*)addr;


	if (ipv6 == 0)
	{
		if (!paddr)
		{
			auto ad = ac.new_obj<sockaddr_in>();
			paddr = (struct sockaddr*)ad;
		}
		r = uv_ip4_addr("0.0.0.0", 0, (sockaddr_in*)paddr);
		r = uv_udp_bind(cli, (const struct sockaddr*)paddr, 0);
		if (0 != uv_ip4_addr(ip, port, (sockaddr_in*)paddr))return 1;
	}
	else
	{
		if (!paddr)
		{
			auto ad = ac.new_obj<sockaddr_in6>();
			paddr = (struct sockaddr*)ad;
		}
		r = uv_ip6_addr("::", 0, (sockaddr_in6*)paddr);
		r = uv_udp_bind(cli, (const struct sockaddr*)paddr, 0);
		if (0 != uv_ip6_addr(ip, port, (sockaddr_in6*)paddr))return 1;
	}
	return r;
}

void cl_recv_cb(uv_udp_t* handle,
	ssize_t nread,
	const uv_buf_t* buf,
	const struct sockaddr* addr,
	unsigned flags) {
	//CHECK_HANDLE(handle);
	assert(flags == 0);

	if (nread < 0) {
		assert(0 && "unexpected error");
	}

	if (nread == 0) {
		return;
	}
	auto p = (udpc_cx*)handle->data;
	if (p && p->rcb)
	{
		p->rcb(buf->base, buf->len);
	}
}

static void alloc_cb(uv_handle_t* handle,
	size_t suggested_size,
	uv_buf_t* buf) {
	static char slab[65536] = {};
	//CHECK_HANDLE(handle);
	assert(suggested_size <= sizeof(slab));
	buf->base = slab;
	buf->len = sizeof(slab);
}

void base_uv::us_cb(uv_udp_send_t* req, int status)
{
	if (req)
	{
		auto p = (base_uv*)req->handle->data;
		auto r = uv_udp_recv_start(req->handle, alloc_cb, cl_recv_cb);
		if (p && req->data)
		{
			p->lk.lock();
			p->ac.free_obj(req);
			p->lk.unlock();
		}
	}
}
void udpc_cx::send_datas()
{
	if (_data.size())
	{
		lk.lock();
		for (; _data.size();)
		{
			auto p = _data.front();
			if (p.base && p.len)
			{
				uv_buf_t buf = uv_buf_init((char*)p.base, p.len);
				assert(p.len <= udpmaxs);
				if (p.req)
					uv_udp_send(p.req, cli, &buf, 1, paddr, us_cb);
				else
					uv_udp_try_send(cli, &buf, 1, paddr);
			}
			_data.pop();
		}
		lk.unlock();
	}
}

void udpc_cx::send_data(const void* d, int size, bool is_req)
{
	static int ka = 0;
	ka++;
	if (!d || size < 1)return;
	lk.lock();
	udp_buf_t b = {};
	b.base = (char*)d;
	b.len = size;
	if (is_req)
		b.req = ac.new_obj<uv_udp_send_t>();
	_data.push(b);
#if 0
	int len = size;
	int chunks = len / udpmaxs;
	int remainder = len % udpmaxs;
	int total = chunks;
	if (remainder > 0)
	{
		total++;
	}
	char* pt = (char*)d;
	for (size_t i = 0; i < chunks; i++)
	{
		udp_buf_t b = {};
		b.req = ac.new_obj<uv_udp_send_t>();
		b.base = (char*)ac.new_mem(udpmaxs + sizeof(int));
		b.len = udpmaxs;
		*((int*)b.base) = sizeof(int) + udpmaxs;
		b.base += sizeof(int);
		b.addr = b.base + sizeof(int);
		memcpy(b.base, pt, udpmaxs);
		_data.push(b);
		pt += udpmaxs;
	}
	if (remainder > 0)
	{
		udp_buf_t b = {};
		b.req = ac.new_obj<uv_udp_send_t>();
		b.base = (char*)ac.new_mem(remainder + sizeof(int));
		b.len = remainder;
		*((int*)b.base) = sizeof(int) + remainder;
		b.base += sizeof(int);
		b.addr = b.base + sizeof(int);
		memcpy(b.base, pt, remainder);
		_data.push(b);
		pt += remainder;
}
#endif
	lk.unlock();
	post();
}
void udpc_cx::send_data_try(const void* d, int size)
{
	if (!d || size < 1)return;
	lk.lock();
	udp_buf_t b = {};
	b.base = (char*)d;
	b.len = size;
	_data.push(b);
	lk.unlock();
}
void udpc_cx::post()
{
	if (_async)
	{
		uv_async_send(_async);
	}
	else
	{
		send_datas();
	}

}

void udpc_cx::send_data_try0(const void* d, int size)
{
	if (!d || size < 1)return;
	udp_buf_t b = {};
	b.base = (char*)d;
	b.len = size;
	_data.push(b);
}
void udpc_cx::lock()
{
	lk.lock();
}
void udpc_cx::unlock()
{
	lk.unlock();
}
void udpc_cx::set_recv_cb(std::function<void(char* d, int len)> cb)
{
	rcb = cb;
}

// udp服务器
udps_cx::udps_cx()
{
	ptr = ac.new_obj<uv_udp_t>();
	ptr->data = this;
}

udps_cx::~udps_cx()
{
	ac.free_obj(ptr);
}

static void slab_alloc(uv_handle_t* handle,
	size_t suggested_size,
	uv_buf_t* buf) {
	/* up to 16 datagrams at once */
	const size_t ss = 16 * 64 * 1024;
	auto p = (udps_cx*)handle->data;
	if (p)
	{
		if (p->b.len < ss)
		{
			p->ac.free_mem(p->b.base, p->b.len);
			p->ac.new_mem(p->b.base, ss);
			p->b.len = ss;
		}
		buf->base = p->b.base;
		buf->len = ss;
		return;
	}
	static char slab[ss];
	buf->base = slab;
	buf->len = sizeof(slab);
}

int udps_cx::bind(int port, int ipv6, const char* ip)
{
	int r = 0;
	auto addr = (get_addr(port, ipv6, ip));

	if (0 != r)return 1;

	r = uv_udp_init(loop, ptr);
	if (r) {
		fprintf(stderr, "uv_udp_init: %s\n", uv_strerror(r));
		return 1;
	}

	r = uv_udp_bind(ptr, (const struct sockaddr*)&addr, 0);
	if (r) {
		fprintf(stderr, "uv_udp_bind: %s\n", uv_strerror(r));
		return 1;
	}
	int ks[] = { sizeof(sockaddr_in), sizeof(sockaddr_in6) };
	r = uv_udp_recv_start(ptr, slab_alloc, on_recv);
	if (r) {
		fprintf(stderr, "uv_udp_recv_start: %s\n", uv_strerror(r));
		return 1;
	}
	sem = run_loop(loop, r);
	return 0;
}

void udps_cx::wait()
{
	if (sem)
		sem->wait();
}

void udps_cx::send_data(const void* addr, const char* d, int size)
{
	if (!d || size < 1)return;
	lk.lock();
	int ss[] = { sizeof(sockaddr_in), sizeof(sockaddr_in6) };
	auto ap = (sockaddr*)addr;
	int v6 = ap->sa_family == AF_INET6 ? ss[1] : ss[0];
	udp_buf_t b = {};
	b.req = ac.new_obj<uv_udp_send_t>();
	int as = size + sizeof(int) + v6;
	auto t = (char*)ac.new_mem(as);
	b.len = size;
	*((int*)t) = as;
	b.addr = t + sizeof(int);
	b.base = t + sizeof(int) + v6;
	memcpy(b.addr, addr, v6);
	memcpy(b.base, d, size);
	_data.push(b);
	lk.unlock();
	if (_async)
	{
		uv_async_send(_async);
	}
	else
	{
		send_datas();
	}
}

void base_uv::us_cbs(uv_udp_send_t* req, int status)
{
	if (req)
	{
		auto p = (base_uv*)req->handle->data;
		//auto r = uv_udp_recv_start(req->handle, alloc_cb, cl_recv_cb);
		if (p && req->data)
		{
			p->lk.lock();
			p->ac.free_mem((char*)req->data, *(int*)req->data);
			p->ac.free_obj(req);

			p->lk.unlock();
		}
	}
}
void udps_cx::send_datas()
{
	if (_data.size())
	{
		const size_t ss = udpmaxs;
		lk.lock();
		for (; _data.size();)
		{
			auto p = _data.front();
			if (p.base && p.len)
			{
				int len = p.len;
				int chunks = len / ss;
				int remainder = len % ss;
				int total = chunks;
				if (remainder > 0)
				{
					total++;
				}
				char* pt = (char*)p.base;
				p.req->data = (char*)p.addr - sizeof(int);
				for (size_t i = 0; i < chunks; i++)
				{
					uv_buf_t buf = uv_buf_init(pt, ss);
					//uv_udp_send(p.req, ptr, &buf, 1, (sockaddr*)p.addr, total - 1 == i ? us_cbs : nullptr);
					uv_udp_try_send(ptr, &buf, 1, (sockaddr*)p.addr);
					pt += ss;
				}
				if (remainder > 0)
				{
					uv_buf_t buf = uv_buf_init(pt, remainder);
					//uv_udp_send(p.req, ptr, &buf, 1, (sockaddr*)p.addr, us_cbs);
					uv_udp_try_send(ptr, &buf, 1, (sockaddr*)p.addr);
				}
			}
			_data.pop();
		}
		lk.unlock();
	}
}
void udps_cx::on_recv(uv_udp_t* handle,
	ssize_t nread,
	const uv_buf_t* rcvbuf,
	const struct sockaddr* addr,
	unsigned flags) {

	static std::string str;
	auto p = (udps_cx*)handle->data;
	//printf("%d\n", nread);
	if (!p || nread == 0) {
		/* Everything OK, but nothing read. */
		return;
	}
	assert(nread > 0);
	assert(addr->sa_family == AF_INET || addr->sa_family == AF_INET6);

	if (p->rcb)
	{
		p->rcb((void*)addr, rcvbuf->base, nread);
	}
	else
	{
		if (rcvbuf->len)
		{
			str.assign(rcvbuf->base, nread);
		}
		printf("udp:%p\t%s\n", handle, str.c_str());
		//p->send_data(addr, "123", 3);
	}
}










// 导出接口
udpc_cx* new_udp_cl(const char* ip, int port, int ipv6)
{
	udpc_cx* p = new udpc_cx();
	if (p)
	{
		p->set_ip(ip, port, ipv6);
		p->sem = run_loop(p->loop, 0);
	}
	return p;
}
void free_udp_cl(udpc_cx* p)
{
	if (p)delete p;
}
tcpc_cx* new_tcp_cl(const char* ip, int port, int ipv6)
{
	auto tcp = new tcpc_cx();
	if (tcp->conntect(ip, port, ipv6) == 0) {
		return tcp;
	}
	delete tcp;
	return nullptr;
}
void free_tcp_cl(tcpc_cx* p)
{
	if (p)
	{
		delete p;
	}
}
