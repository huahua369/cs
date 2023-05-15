// uvtest.cpp: 定义应用程序的入口点。
//

#include <string>
#include "cs.h"
#include <uv.h>
using namespace std;

int main()
{
	cout << "Hello client." << endl;
	const char* ip = "127.0.0.1";
	const char* ip6 = "::1";
	int ipv6 = 0;
	int port = 9123;
	tcpc_cx* tcp = new_tcp_cl(ipv6 ? ip6 : ip, port, ipv6);
	if (tcp)
	{
		tcp->set_recv_cb([=](char* d, int len) {
			{
				std::string str;
				if (len)
				{
					str.assign(d, len);
				}
				printf("收到 %s\n", str.c_str());
			}
			});
		tcp->run();
	}
	udpc_cx* p = new_udp_cl(ipv6 ? ip6 : ip, port, ipv6);
	p->set_recv_cb([=](char* d, int len) {
		{
			std::string str;
			if (len)
			{
				str.assign(d, len);
			}
			printf("收到 %s\n", str.c_str());
		}
		});

	int ss[] = { sizeof(sockaddr_in), sizeof(sockaddr_in6) };
	std::string str;
	while (str != "q")
	{
		cin >> str;
		if (str == "1")
		{
			if (tcp)
				tcp->reset_connect(); continue;
		}
		if (str.size())
		{
			//if (tcp)
			tcp->send_data(str.c_str(), str.size());
			//for (size_t i = 0; i < 1024 * 1024; i++)
			{
				p->send_data(str.c_str(), str.size(), false);
			}
			//if (p)
			//	p->send_data(str.c_str(), str.size());
		}
	}
	free_tcp_cl(tcp);
	free_udp_cl(p);
	return 0;
}
#ifndef _WIN32
#include <netinet/in.h> // sockaddr_in

#include <sys/types.h> // socket

#include <sys/socket.h> // socket
#endif
#include <stdio.h> // printf

#include <stdlib.h> // exit

#include <string.h> // bzero
#include <time.h>       // bzero
#include <math.h>       // bzero
#pragma comment(lib,"ws2_32.lib")


#define LENGTH_OF_LISTEN_QUEUE 20
// 1.36G/s
#define BUFFER_SIZE (1024*64-256)
// 1G/s
#define BUFFER_SIZE1 (1024*32)

#define FILE_NAME_MAX_SIZE 512

int maina(void)
{
#ifdef _WIN32

	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(1, 1);
	auto err = WSAStartup(wVersionRequested, &wsaData);
#endif // _WIN32

	int nsend_buf_len = 13 * 1024;
	int nlen = sizeof(int);

	int byte_recv = 0, nread = 0;
	struct timespec time_start = { 0, 0 }, time_end = { 0, 0 };
	struct sockaddr_in client_addr = {};

	client_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &client_addr.sin_addr);
	client_addr.sin_port = htons(9123);

	int client_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (client_socket_fd < 0) {
		perror("Create Socket Failed:");

		auto	err = WSAGetLastError();
		auto es = uv_translate_sys_error(err);
		auto stre = uv_strerror(es);

		exit(1);
	}

	while (1) {
		char* buffer = NULL;
		buffer = (char*)malloc(BUFFER_SIZE + 1);
		memset(buffer, 0, BUFFER_SIZE);
		int nwrite = 0;
		int byte_send = 0, byte_recv = 0;
		int ret = 0;
		//ret = connect(client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr));
		if (ret < 0) {
			perror("connect fail\n");
			exit(1);
		}
		printf("client connect: 127.0.0.1\n");
		//        setsockopt(client_socket_fd,SOL_SOCKET,SO_SNDBUF,(char*)&nsend_buf_len,nlen);

		while (1) {
#if 0
			nread = recv(client_socket_fd, buffer, BUFFER_SIZE, 0);
			if (nread > 0) {
				//      printf("nread %d\n", nread);
			}
			else {
				printf("--1--connect_close?-- %d", nread);
				break;
			}
#endif

			//nwrite = send(client_socket_fd, buffer, BUFFER_SIZE, 0);
			nwrite = sendto(client_socket_fd, buffer, BUFFER_SIZE, 0, (sockaddr*)&client_addr, sizeof(client_addr));
			if (nwrite > 0) {
				//      printf("send %d\n", nwrite);
			}
			else {
				printf("--2--connect_close?-- %d", nwrite);
				break;
			}
		}

		free(buffer);
		printf("socket close\n");
	}
#if _WIN32
	closesocket(client_socket_fd);
#else
	close(client_socket_fd);
#endif // _WIN32

	printf("socket close\n");
	return 0;
}
