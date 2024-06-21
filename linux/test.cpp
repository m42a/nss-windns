#include <iostream>
#include <algorithm>
#include <string>
#include <bit>

#include <cstdlib>
#include <cstring>

#include <nss.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace
{
	in6_addr byteswap(in6_addr in6)
	{
		std::ranges::reverse(in6.s6_addr);
		return in6;
	}

	void lookup_addr_impl(const sockaddr *addr, socklen_t addr_len)
	{
		char name_buf[1024]{};
		char serv_buf[1024]{};
		auto gni_ret = getnameinfo(addr, addr_len, name_buf, sizeof(name_buf), serv_buf, sizeof(serv_buf), 0);
		if (gni_ret != 0)
		{
			std::cerr << "getnameinfo error: " << gai_strerror(gni_ret) << '\n';
		}
		else
		{
			std::cout << "Got name '" << name_buf << "' and service '" << serv_buf << "'\n";
		}
	}

	void lookup_addr(const in_addr_t &addr)
	{
		char addr_buf[128]{};
		auto addr_str = inet_ntop(AF_INET, &addr, addr_buf, sizeof(addr_buf));
		std::cout << "Looking up ipv4 address " << addr_str << '\n';
		sockaddr_in lookup{
			.sin_family = AF_INET,
			.sin_port = 0x5000,
			.sin_addr = addr,
		};
		lookup_addr_impl((const sockaddr *)&lookup, sizeof(lookup));
	}

	void lookup_addr(const in6_addr &addr)
	{
		char addr_buf[128]{};
		auto addr_str = inet_ntop(AF_INET6, &addr, addr_buf, sizeof(addr_buf));
		std::cout << "Looking up ipv6 address " << addr_str << '\n';
		sockaddr_in6 lookup{
			.sin6_family = AF_INET6,
			.sin6_port = 0x5000,
			.sin6_addr = addr,
		};
		lookup_addr_impl((const sockaddr *)&lookup, sizeof(lookup));
	}

	void lookup_name(const char *name, int family = AF_UNSPEC)
	{
		const addrinfo hints {
			.ai_flags = AI_CANONNAME,
			.ai_family = family,
			.ai_socktype = SOCK_STREAM,
		};
		std::cout << "Looking up name " << name << '\n';
		addrinfo *resolved_info{};
		auto gai_ret = getaddrinfo(name, "http", &hints, &resolved_info);
		if (gai_ret != 0)
		{
			auto e = errno;
			std::cerr << "getaddrinfo error: " << gai_strerror(gai_ret) << '\n';
			if (gai_ret == EAI_SYSTEM)
				std::cerr << "\terrno: " << strerror(e) << '\n';
			return;
		}
		std::cout << "getaddrinfo succeeded. hosts:\n";
		for (auto info = resolved_info; info; info=info->ai_next)
		{
			switch (info->ai_family)
			{
			case AF_INET:
			{
				auto in = reinterpret_cast<const sockaddr_in *>(info->ai_addr);
				char addr_buf[128]{};
				auto addr_str = inet_ntop(in->sin_family, &in->sin_addr, addr_buf, sizeof(addr_buf));
				std::cout << "\tAddress " << addr_str << " flags=" << info->ai_flags << " type=" << info->ai_socktype << " proto=" << info->ai_protocol;
				break;
			}
			case AF_INET6:
			{
				auto in6 = reinterpret_cast<const sockaddr_in6 *>(info->ai_addr);
				char addr_buf[128]{};
				auto addr_str = inet_ntop(in6->sin6_family, &in6->sin6_addr, addr_buf, sizeof(addr_buf));
				std::cout << "\tAddress " << addr_str << " flags=" << info->ai_flags << " type=" << info->ai_socktype << " proto=" << info->ai_protocol;
				break;
			}
			default:
				std::cout << "\tUnknown family " << info->ai_family;
				break;
			}
			if (info->ai_canonname)
				std::cout << " Canon name '" << info->ai_canonname << "'";
			std::cout << '\n';
		}
	}
}

int main()
{
	__nss_configure_lookup("hosts", "windns");

	lookup_addr(INADDR_LOOPBACK);
	lookup_addr(std::byteswap(INADDR_LOOPBACK));
	lookup_addr(in6addr_loopback);
	lookup_addr(byteswap(in6addr_loopback));

	lookup_name("test-ipv6.com"); // v4 only
	lookup_name("ipv6.test-ipv6.com"); // v6 only
	lookup_name("ds.test-ipv6.com"); // both
	lookup_name("ds.test-ipv6.com", AF_INET);
	lookup_name("ds.test-ipv6.com", AF_INET6);

	lookup_name("ουτοπία.δπθ.gr"); // idn
}
