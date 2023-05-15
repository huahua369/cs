// uvtest.h: 标准系统包含文件的包含文件
/*
重要：loop run以后就不要在loop以外线程调用uv函数

*/

#pragma once

#include <iostream>
#include <queue>
#include <map>
#include <string>
#include <mutex>
#include <thread>
#include <functional>

// TODO: 在此处引用程序需要的其他标头。

#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
# define SSIZE_MAX INTPTR_MAX
# define _SSIZE_T_
# define _SSIZE_T_DEFINED
#endif

#ifdef __cplusplus
extern "C" {
#endif
	typedef void* uv_sem_t;
	typedef struct uv_udp_s uv_udp_t;
	typedef struct uv_loop_s uv_loop_t;
	typedef struct uv_async_s uv_async_t;
	typedef struct uv_udp_send_s uv_udp_send_t;
	typedef struct uv_tcp_s uv_tcp_t;
	typedef struct uv_connect_s uv_connect_t;
	typedef struct uv_write_s uv_write_t;
	typedef struct uv_stream_s uv_stream_t;
	typedef struct uv_handle_s uv_handle_t;
	struct uv_buf_t;
#ifdef __cplusplus
}


#include <memory_resource>

template<class _Ty>
using pmalloc_t = std::pmr::polymorphic_allocator<_Ty>;		// 指定类型内存分配
using uspool_t = std::pmr::unsynchronized_pool_resource;	// 线程不安全
using mbpool_t = std::pmr::monotonic_buffer_resource;		// 线程不安全，多次分配，统一释放
using spool_t = std::pmr::synchronized_pool_resource;		// 线程安全的


#ifdef max
#undef max
#undef min
#endif // max
#define maxblock_ss 1024*1024
class usp_ac
{
public:
	uspool_t _alloc = {};				// pmr内存分配
	size_t _Align = 16;
public:
	usp_ac() {}
	~usp_ac() {}
public:
	void* new_mem(size_t n)
	{
		n = std::max((size_t)1, n);
		void* p = 0;
		if (n < maxblock_ss)
			p = _alloc.allocate(n, _Align);
		else
			p = alloc_m(n, _Align);
		memset(p, 0, n);
		return p;
	}
	template<class T>
	T* new_mem(size_t n)
	{
		n = std::max((size_t)1, n);
		auto p = (T*)_alloc.allocate(sizeof(T) * n, _Align);
		auto ptr = p;
		for (int i = 0; i < n; i++)
		{
			p[i] = {};
		}
		return p;
	}
	template<class T >
	T* new_mem(size_t n, T*& p)
	{
		n = std::max((size_t)1, n);
		p = (T*)_alloc.allocate(sizeof(T) * n, _Align);
		auto ptr = p;
		for (int i = 0; i < n; i++)
		{
			p[i] = {};
		}
		return p;
	}
	template<class T>
	T* new_mem(T*& p, size_t n)
	{
		return new_mem(n, p);
	}
	template<class T>
	void free_mem(T* t, size_t n)
	{
		auto ptr = t;
		if (t && n > 0)
		{
			if (n < maxblock_ss)
			{
				_alloc.deallocate(t, sizeof(T) * n, _Align);
			}
			else
			{
				free_m(t);
			}
		}
	}
	template<class T, class... Ts>
	T* new_obj(Ts &&... args)
	{
		auto p = (T*)new_mem(sizeof(T));
		if (p)
			std::uninitialized_construct_using_allocator(p, _alloc, std::forward<Ts>(args)...);
		return p;
	}
	template<class T>
	void free_obj(T* t)
	{
		auto ptr = t;
		if (t)
		{
			std::destroy_at(ptr);
			free_mem(t, 1);
			//_alloc.deallocate(t, sizeof(T), _Align);
		}
	}
	template<typename T> inline T alignUp(const T& val, T alignment)
	{
		T r = (val + alignment - (T)1) & ~(alignment - (T)1);
		return r;
	}
	void* alloc_m(size_t size, size_t a)
	{
		auto ns = alignUp(size, a);
		return ns > 0 ? malloc(ns) : nullptr;
	}
	void free_m(void* p)
	{
		if (p)
			free(p);
	}
};




#endif




// 线程句柄判断用
class sem_st
{
public:
	uv_sem_t* sem = 0;
	std::thread a;
public:
	sem_st();
	~sem_st();
	void post();
	int wait(int ms = 0);
	// 返回0则有信号，1无信号
	int wait_try();

	void join();
private:

};

struct buf_tx
{
	uint32_t len;
	char* base;
};

class base_uv
{
public:
	uv_async_t* _async = 0;
	// 内存分配
	usp_ac ac;
	// 读取缓存区
	buf_tx b = {};
	uv_loop_t* loop = 0;
	sem_st* sem = 0;
	std::function<void()> acb;
	std::mutex lk;
public:
	base_uv();
	virtual	~base_uv();

	virtual	void send_data(const void* d, int size);
	// 线程调用
	virtual	void send_datas();
	static void async_cb(uv_async_t* handle);
	static void us_cb(uv_udp_send_t* req, int status);
	static void us_cbs(uv_udp_send_t* req, int status);
private:

};




struct udp_buf_t
{
	uint32_t len = 0;
	char* base = 0;
	uv_udp_send_t* req = 0;
	void* addr = 0;
};


// udp客户端
class udpc_cx :public base_uv
{
public:
	uv_udp_t* cli = 0;
	struct sockaddr* paddr = 0;
	std::function<void(char* d, int len)> rcb; // 读回调
	std::queue<udp_buf_t> _data;

public:
	udpc_cx();
	~udpc_cx();
	int set_ip(const char* ip, int port, int ipv6);
	void set_recv_cb(std::function<void(char* d, int len)> cb);
	void send_data(const void* d, int size, bool is_req);
	// 1472byte
	void send_data_try(const void* d, int len);
	void post();

	void send_data_try0(const void* d, int len);
	void lock();
	void unlock();
private:
	// 线程调用
	void send_datas();
};
// udp服务端
class udps_cx :public base_uv
{
public:
	uv_udp_t* ptr;
	std::function<void(void* addr, char* d, int len)> rcb;
	std::queue<udp_buf_t> _data;

public:
	udps_cx();
	~udps_cx();

	int bind(int port, int ipv6, const char* ip = 0);
	void wait();
	void send_data(const void* addr, const char* d, int len);
private:
	void send_datas();
	static void on_recv(uv_udp_t* handle,
		ssize_t nread,
		const uv_buf_t* rcvbuf,
		const struct sockaddr* addr,
		unsigned flags);
};


// 连接的客户端
class client_cx
{
public:
	// 内存分配
	usp_ac ac = {};
	// 读取缓存区
	buf_tx b = {};
	// 
	uv_stream_t* stream = 0;

	std::function<void(client_cx*, char* d, int len)>* rcb = 0;
public:
	client_cx();
	~client_cx();

	void read_u(ssize_t nread, const uv_buf_t* buf);
	void accept_u(uv_stream_t* server);
	static void c_after_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);
	static void u_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

	static void close_cb(uv_handle_t* handle);
private:

};

// tcp服务端
class tcps_cx :public base_uv
{
public:
	uv_tcp_t* ptr = 0;

	std::function<void(client_cx*, char* d, int len)> rcb;
	std::function<void(client_cx*)> conn_cb;
public:
	tcps_cx();
	~tcps_cx();
	// 0绑定到127.0.0.1
	void bind(int port, int ipv6, const char* ip = 0);
	void wait();
private:
	static void on_connection(uv_stream_t* server, int status);
};
// tcp客户端
class tcpc_cx :public base_uv
{
public:
	uv_tcp_t* cli = 0;
	struct sockaddr* paddr = 0;
	uv_connect_t* ctp = 0;
	//uv_write_t* uvreq = 0;

	std::queue<buf_tx> _data;
	std::function<void(char* d, int len)> rcb;

	int rs = 0;
public:
	tcpc_cx();
	~tcpc_cx();
	// 连接到ip端口
	int conntect(const char* ip, int port, int ipv6);
	void reset_connect();

	void set_recv_cb(std::function<void(char* d, int len)> cb);
	void run();
	void send_data(const void* d, int size);
	void send_data_try(const void* d, int size);
	void post();
private:
	void send_datas();
	void on_connect(uv_connect_t* req, int status);
	static void on_connect1(uv_connect_t* req, int status);
};


// 默认分配16字节对齐
void* alloc_m(size_t size, size_t a = 16);
void  free_m(void* p);
// 返回1则支持ipv6
int canipv6();

// 客户端
tcpc_cx* new_tcp_cl(const char* ip, int port, int ipv6);
void free_tcp_cl(tcpc_cx* p);

udpc_cx* new_udp_cl(const char* ip, int port, int ipv6);
void free_udp_cl(udpc_cx* p);
