// uvtest.cpp: 定义应用程序的入口点。
//

#include <string>
#include "cs.h"
using namespace std;

int main()
{
	cout << "Hello client." << endl;
	const char* ip = "127.0.0.1";
	const char* ip6 = "::1";
	int ipv6 = 1;
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
			if (tcp)
				tcp->send_data(str.c_str(), str.size());
			if (p)
				p->send_data(str.c_str(), str.size());
		}
	}
	free_tcp_cl(tcp);
	free_udp_cl(p);
	return 0;
}
