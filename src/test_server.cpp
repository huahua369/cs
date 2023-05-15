// uvtest.cpp: 定义应用程序的入口点。
//

#include "cs.h"


#ifdef _WIN32
# define TEST_PIPENAME "\\\\?\\pipe\\uv-test"
# define TEST_PIPENAME_2 "\\\\?\\pipe\\uv-test2"
# define TEST_PIPENAME_3 "\\\\?\\pipe\\uv-test3"
#else
# define TEST_PIPENAME "/tmp/uv-test-sock"
# define TEST_PIPENAME_2 "/tmp/uv-test-sock2"
# define TEST_PIPENAME_3 "/tmp/uv-test-sock3"
#endif

using namespace std;

int main()
{
	cout << "Hello server." << canipv6() << endl;
	int ip6 = 0;
	int port = 9123;
	const char* pipename = TEST_PIPENAME;
	tcps_cx* tcp = new tcps_cx();
	tcp->bind(port, ip6, 0);
	udps_cx* udp = new udps_cx();
	udp->bind(port, ip6, 0);
	tcp->wait();
	udp->wait();
	return 0;
}
