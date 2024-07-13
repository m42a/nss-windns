#include <span>
#include <string_view>

#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <errno.h>
#include <nss.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace std::literals;

namespace
{
	struct temp_fd
	{
		int fd = -1;

		explicit temp_fd(int fd) : fd(fd) {}
		temp_fd(const temp_fd &) = delete;

		bool valid() const
		{
			return fd != -1;
		}

		void close()
		{
			if (valid())
			{
				::close(fd);
				fd = -1;
			}
		}

		operator int() const
		{
			return fd;
		}

		~temp_fd()
		{
			close();
		}
	};

	void set_path(sockaddr_un &addr, std::string_view path)
	{
		if (path.size() >= sizeof(addr.sun_path))
		{
			addr.sun_path[0] = '\0';
			return;
		}
		memcpy(addr.sun_path, path.data(), path.size());
		addr.sun_path[path.size()] = '\0';
	}

	sockaddr_un init_windns_sockaddr()
	{
		sockaddr_un ret {
			.sun_family = AF_UNIX
		};
		auto env_path = getenv("WINDNS_SOCKET");
		if (env_path && *env_path)
		{
			set_path(ret, env_path);
			return ret;
		}
		auto home = getenv("HOME");
		if (!home || !*home)
			return ret;

		char socket_path_buf[PATH_MAX];
		size_t socket_path_len = 0;
#define APPEND(STR) do { \
			std::string_view sv(STR); \
			if (sv.size() > sizeof(socket_path_buf) - socket_path_len) return ret; \
			memcpy(socket_path_buf + socket_path_len, sv.data(), sv.size()); \
			socket_path_len += sv.size(); \
		} while (0)

		APPEND(home);
		// We know home is not empty, so socket_path_len will never be 0
		if (socket_path_buf[socket_path_len-1] != '/')
			APPEND("/"sv);
		APPEND(".windns.socket\0"sv);
#undef APPEND
		// WSL differentiates between "WSL" unix sockets and "Win32" unix sockets based on the socket path (see https://devblogs.microsoft.com/commandline/windowswsl-interop-with-af_unix/). This does not resolve symlinks first, so we need to manually follow the link in order to create the right type of unix socket.
		char real_socket_path_buf[PATH_MAX+1];
		auto real_path = realpath(socket_path_buf, real_socket_path_buf);
		if (!real_path)
			return ret;
		set_path(ret, real_path);
		return ret;
	}

	// We have to use a global constructor to initialize this because delaying it until use requires the __cxa_guard_* functions which are in libstdc++, and _nss_*_init is only called from nscd (https://github.com/bminor/glibc/blob/85472c20a55ea2a49a7fbdf71652b4009118b0ae/nss/nss_module.c#L244)
	sockaddr_un windns_sockaddr = init_windns_sockaddr();

	struct addr_buf
	{
		char data[1+sizeof(in6_addr)];

		static addr_buf from4(const in_addr &in4)
		{
			addr_buf ret{};
			ret.data[0] = '4';
			memcpy(ret.data+1, &in4, sizeof(in4));
			return ret;
		}

		static addr_buf from6(const in6_addr &in6)
		{
			addr_buf ret{};
			ret.data[0] = '6';
			memcpy(ret.data+1, &in6, sizeof(in6));
			return ret;
		}

		bool is4() const
		{
			return data[0] == '4';
		}

		bool is6() const
		{
			return data[0] == '6';
		}

		size_t size() const
		{
			if (data[0] == '4')
				return 1 + sizeof(in_addr);
			return 1 + sizeof(in6_addr);
		}
	};

	static constexpr std::string_view name_prefix = "name "sv;
	static constexpr std::string_view addr_prefix = "addr "sv;

	struct response_buf
	{
		static constexpr size_t max_length = 4096;

		int error = 0;
		uint16_t length = 0;
		char buf[max_length];

		std::string_view to_sv() const
		{
			return std::string_view(buf, length);
		}

		std::span<const char> to_span() const
		{
			return std::span<const char>(buf, length);
		}

		bool has_prefix(std::string_view prefix) const
		{
			return to_sv().starts_with(prefix);
		}

		bool is_name() const
		{
			return has_prefix(name_prefix);
		}

		bool is_addr() const
		{
			return has_prefix(addr_prefix);
		}
	};

	response_buf send_request(std::string_view request_prefix, iovec request_data)
	{
		response_buf ret;
		if (windns_sockaddr.sun_path[0] == '\0')
		{
			ret.error = ENOENT;
			return ret;
		}
		temp_fd sock(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
		if (!sock.valid())
		{
			ret.error = errno;
			return ret;
		}

		auto connect_ret = connect(sock, reinterpret_cast<const sockaddr *>(&windns_sockaddr), sizeof(windns_sockaddr));
		if (connect_ret == -1)
		{
			ret.error = errno;
			return ret;
		}

		// The timeouts have to be set after connecting, otherwise the connect fails
		timeval timeout{
			.tv_sec = 30,
			.tv_usec = 0
		};

		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		iovec send_data[] = {
			{
				.iov_base = const_cast<void *>(static_cast<const void *>(request_prefix.data())),
				.iov_len = request_prefix.size()
			},
			request_data
		};
		msghdr send_msg = {
			.msg_iov = send_data,
			.msg_iovlen = std::extent_v<decltype(send_data)>
		};

		auto sendmsg_ret = sendmsg(sock, &send_msg, MSG_NOSIGNAL);
		if (sendmsg_ret == -1)
		{
			ret.error = errno;
			return ret;
		}
		// TODO: Ensure the message didn't tear
		auto shutdown_ret = shutdown(sock, SHUT_WR);
		if (shutdown_ret == -1)
		{
			ret.error = errno;
			return ret;
		}

		// TODO: Receive loop (use poll for timeout behavior?)
		auto recvmsg_ret = recv(sock, ret.buf, ret.max_length, 0);
		if (recvmsg_ret == -1)
		{
			ret.error = errno;
			return ret;
		}
		if (recvmsg_ret >= static_cast<decltype(recvmsg_ret)>(ret.max_length))
		{
			ret.error = ENOBUFS;
			return ret;
		}
		ret.length = recvmsg_ret;
		return ret;
	}

	response_buf send_addr(const addr_buf &lookup_addr)
	{
		iovec addr_iov = {
			.iov_base = const_cast<void *>(static_cast<const void *>(lookup_addr.data)),
			.iov_len = lookup_addr.size()
		};
		return send_request(addr_prefix, addr_iov);
	}

	response_buf send_name(std::string_view lookup_name)
	{
		iovec name_iov = {
			.iov_base = const_cast<void *>(static_cast<const void *>(lookup_name.data())),
			.iov_len = lookup_name.size()
		};
		return send_request(name_prefix, name_iov);
	}

	struct host_func_ret
	{
		nss_status func_ret;
		int errno_;
		int h_errno_;
	};

	host_func_ret gethostbyaddr_impl(std::span<const std::byte> lookup_addr_span, int lookup_family, hostent *result, std::span<char> buf, int32_t *ttl_p)
	{
		if (ttl_p)
			*ttl_p = 0;

		addr_buf lookup_addr;
		if (lookup_family == AF_INET)
		{
			if (lookup_addr_span.size() < sizeof(in_addr))
				return {
					.func_ret = NSS_STATUS_UNAVAIL,
					.errno_ = EINVAL,
					.h_errno_ = NETDB_INTERNAL
				};
			auto lookup_in_addr = reinterpret_cast<const in_addr *>(lookup_addr_span.data());
			lookup_addr = addr_buf::from4(*lookup_in_addr);
		}
		else if (lookup_family == AF_INET6)
		{
			if (lookup_addr_span.size() < sizeof(in6_addr))
				return {
					.func_ret = NSS_STATUS_UNAVAIL,
					.errno_ = EINVAL,
					.h_errno_ = NETDB_INTERNAL
				};
			auto lookup_in6_addr = reinterpret_cast<const in6_addr *>(lookup_addr_span.data());
			lookup_addr = addr_buf::from6(*lookup_in6_addr);
		}
		else
		{
			return {
				.func_ret = NSS_STATUS_UNAVAIL,
				.errno_ = EAFNOSUPPORT,
				.h_errno_ = NETDB_INTERNAL
			};
		}
		auto response = send_addr(lookup_addr);
		if (!response.is_name())
		{
			if (response.error == 0)
				response.error = ENOENT;
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = response.error,
				.h_errno_ = HOST_NOT_FOUND
			};
		}
		auto name_str = response.to_sv().substr(name_prefix.size());
		if (name_str.empty())
		{
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = ENOENT,
				.h_errno_ = HOST_NOT_FOUND
			};
		}

		auto buf_cur = buf;
#define COPY(DATA, LEN) do { \
			const void *data = DATA; \
			size_t len = LEN; \
			if (buf_cur.size() < len) \
				return { .func_ret = NSS_STATUS_TRYAGAIN, .errno_ = ERANGE, .h_errno_ = NETDB_INTERNAL }; \
			memcpy(buf_cur.data(), data, len); \
			buf_cur = buf_cur.subspan(len); \
		} while (0)
#define COPY_ELEM(ELEM) COPY(&(ELEM), sizeof(ELEM))
		auto addr_ptr = buf_cur.data();
		if (lookup_family == AF_INET)
		{
			auto in = reinterpret_cast<const sockaddr_in *>(lookup_addr_span.data());
			result->h_length = sizeof(in->sin_addr);
			COPY_ELEM(in->sin_addr);
		}
		else
		{
			auto in6 = reinterpret_cast<const sockaddr_in6 *>(lookup_addr_span.data());
			result->h_length = sizeof(in6->sin6_addr);
			COPY_ELEM(in6->sin6_addr);
		}
		result->h_addr_list = reinterpret_cast<char **>(buf_cur.data());
		COPY_ELEM(addr_ptr);
		addr_ptr = nullptr;
		result->h_aliases = reinterpret_cast<char **>(buf_cur.data());
		COPY_ELEM(addr_ptr);
		result->h_name = buf_cur.data();
		COPY(name_str.data(), name_str.size());
		static constexpr char zero = '\0';
		COPY_ELEM(zero);
		result->h_addrtype = lookup_family;
#undef COPY_ELEM
#undef COPY
		return {
			.func_ret = NSS_STATUS_SUCCESS,
			.errno_ = 0,
			.h_errno_ = 0
		};
	}

	host_func_ret gethostbyname_hostent(std::string_view name, int address_family, hostent *result, std::span<char> buf, int32_t *ttl_p, char **canonp)
	{
		if (!result)
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = EINVAL,
				.h_errno_ = HOST_NOT_FOUND
			};
		if (ttl_p)
			*ttl_p = 0;
		if (canonp)
			*canonp = nullptr;
		if (address_family != AF_INET && address_family != AF_INET6)
			return {
				.func_ret = NSS_STATUS_UNAVAIL,
				.errno_ = EAFNOSUPPORT,
				.h_errno_ = NETDB_INTERNAL
			};
		auto response = send_name(name);
		if (!response.is_addr())
		{
			if (response.error == 0)
				response.error = ENOENT;
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = response.error,
				.h_errno_ = HOST_NOT_FOUND
			};
		}
		auto response_addrs = response.to_sv().substr(addr_prefix.size());
		if (response_addrs.empty())
		{
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = ENOENT,
				.h_errno_ = HOST_NOT_FOUND
			};
		}

		if (address_family == AF_INET)
			result->h_length = sizeof(in_addr);
		else
			result->h_length = sizeof(in6_addr);
		result->h_addrtype = address_family;
		auto buf_cur = buf;
#define COPY(DATA, LEN) do { \
			const void *data = DATA; \
			size_t len = LEN; \
			if (buf_cur.size() < len) \
				return { .func_ret = NSS_STATUS_TRYAGAIN, .errno_ = ERANGE, .h_errno_ = NETDB_INTERNAL }; \
			memcpy(buf_cur.data(), data, len); \
			buf_cur = buf_cur.subspan(len); \
		} while (0)
#define COPY_ELEM(ELEM) COPY(&(ELEM), sizeof(ELEM))
#define PAD(ALIGN) do { \
			size_t align = ALIGN; \
			static constexpr char zero = '\0'; \
			while (reinterpret_cast<intptr_t>(buf_cur.data()) % align != 0) \
				COPY_ELEM(zero); \
		} while (0)
		auto addr_list_ptr = buf_cur.data();
		while (!response_addrs.empty())
		{
			if (response_addrs.front() == '4')
			{
				response_addrs.remove_prefix(1);
				if (response_addrs.size() < sizeof(in_addr))
					return {
						.func_ret = NSS_STATUS_UNAVAIL,
						.errno_ = EBADMSG,
						.h_errno_ = NETDB_INTERNAL
					};
				if (address_family == AF_INET)
					COPY(response_addrs.data(), sizeof(in_addr));
				response_addrs.remove_prefix(sizeof(in_addr));
			}
			else if (response_addrs.front() == '6')
			{
				response_addrs.remove_prefix(1);
				if (response_addrs.size() < sizeof(in6_addr))
					return {
						.func_ret = NSS_STATUS_UNAVAIL,
						.errno_ = EBADMSG,
						.h_errno_ = NETDB_INTERNAL
					};
				if (address_family == AF_INET6)
					COPY(response_addrs.data(), sizeof(in6_addr));
				response_addrs.remove_prefix(sizeof(in6_addr));
			}
			else
			{
				return {
					.func_ret = NSS_STATUS_UNAVAIL,
					.errno_ = EBADMSG,
					.h_errno_ = NETDB_INTERNAL
				};
			}
		}
		auto addr_list_end_ptr = buf_cur.data();
		if (addr_list_ptr == addr_list_end_ptr)
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = ENOENT,
				.h_errno_ = HOST_NOT_FOUND
			};
		for (auto ptr = addr_list_ptr; ptr != addr_list_end_ptr; ptr += result->h_length)
			COPY_ELEM(ptr);
		auto null_term = buf_cur.data();
		void *null = nullptr;
		COPY_ELEM(null);
		result->h_addr_list = reinterpret_cast<char **>(addr_list_end_ptr);
		result->h_aliases = reinterpret_cast<char **>(null_term);
		auto name_addr = buf_cur.data();
		COPY(name.data(), name.size());
		static constexpr char zero = '\0';
		COPY_ELEM(zero);
		result->h_name = name_addr;
#undef PAD
#undef COPY_ELEM
#undef COPY
		return {
			.func_ret = NSS_STATUS_SUCCESS,
			.errno_ = 0,
			.h_errno_ = 0
		};
	}

	host_func_ret gethostbyname_addrtuple(std::string_view name, gaih_addrtuple **result, std::span<char> buf, int32_t *ttl_p)
	{
		if (!result)
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = EINVAL,
				.h_errno_ = HOST_NOT_FOUND
			};
		*result = nullptr;
		if (ttl_p)
			*ttl_p = 0;
		auto response = send_name(name);
		if (!response.is_addr())
		{
			if (response.error == 0)
				response.error = ENOENT;
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = response.error,
				.h_errno_ = HOST_NOT_FOUND
			};
		}
		auto response_addrs = response.to_sv().substr(addr_prefix.size());
		if (response_addrs.empty())
		{
			return {
				.func_ret = NSS_STATUS_NOTFOUND,
				.errno_ = ENOENT,
				.h_errno_ = HOST_NOT_FOUND
			};
		}

		auto buf_cur = buf;
		gaih_addrtuple *last_tuple = nullptr;
#define COPY(DATA, LEN) do { \
			const void *data = DATA; \
			size_t len = LEN; \
			if (buf_cur.size() < len) \
				return { .func_ret = NSS_STATUS_TRYAGAIN, .errno_ = ERANGE, .h_errno_ = NETDB_INTERNAL }; \
			memcpy(buf_cur.data(), data, len); \
			buf_cur = buf_cur.subspan(len); \
		} while (0)
#define COPY_ELEM(ELEM) COPY(&(ELEM), sizeof(ELEM))
#define PAD(ALIGN) do { \
			size_t align = ALIGN; \
			static constexpr char zero = '\0'; \
			while (reinterpret_cast<intptr_t>(buf_cur.data()) % align != 0) \
				COPY_ELEM(zero); \
		} while (0)

		auto name_pos = buf_cur.data();
		COPY(name.data(), name.size());
		static constexpr char zero = '\0';
		COPY_ELEM(zero);
		PAD(alignof(gaih_addrtuple));
		while (!response_addrs.empty())
		{
			gaih_addrtuple next_tuple{
				.next = nullptr,
				.scopeid = 0
			};
			if (response_addrs.front() == '4')
			{
				response_addrs.remove_prefix(1);
				if (response_addrs.size() < sizeof(in_addr))
					return {
						.func_ret = NSS_STATUS_UNAVAIL,
						.errno_ = EBADMSG,
						.h_errno_ = NETDB_INTERNAL
					};
				next_tuple.family = AF_INET;
				memcpy(next_tuple.addr, response_addrs.data(), sizeof(in_addr));
				response_addrs.remove_prefix(sizeof(in_addr));
			}
			else if (response_addrs.front() == '6')
			{
				response_addrs.remove_prefix(1);
				if (response_addrs.size() < sizeof(in6_addr))
					return {
						.func_ret = NSS_STATUS_UNAVAIL,
						.errno_ = EBADMSG,
						.h_errno_ = NETDB_INTERNAL
					};
				next_tuple.family = AF_INET6;
				memcpy(next_tuple.addr, response_addrs.data(), sizeof(in6_addr));
				response_addrs.remove_prefix(sizeof(in6_addr));
			}
			else
			{
				return {
					.func_ret = NSS_STATUS_UNAVAIL,
					.errno_ = EBADMSG,
					.h_errno_ = NETDB_INTERNAL
				};
			}
			auto next_tuple_pos = buf_cur.data();
			COPY_ELEM(next_tuple);
			auto new_last_tuple = reinterpret_cast<gaih_addrtuple *>(next_tuple_pos);
			new_last_tuple->name = name_pos;
			if (last_tuple)
			{
				last_tuple->next = new_last_tuple;
			}
			else
			{
				*result = new_last_tuple;
			}
			last_tuple = new_last_tuple;
		}
#undef PAD
#undef COPY_ELEM
#undef COPY
		return {
			.func_ret = NSS_STATUS_SUCCESS,
			.errno_ = 0,
			.h_errno_ = 0
		};
	}
}

extern "C"
{
	// Declare every nss function, sp we get a compiler error if the prototype is wrong
	NSS_DECLARE_MODULE_FUNCTIONS(windns)
}

// Only define the dns functions
//extern "C" nss_status _nss_windns_getcanonname_r
extern "C" nss_status _nss_windns_gethostbyaddr_r(const void *addr, socklen_t addr_len, int family, hostent *result, char *buf, size_t buf_len, int *errno_p, int *h_errno_p)
{
	return _nss_windns_gethostbyaddr2_r(addr, addr_len, family, result, buf, buf_len, errno_p, h_errno_p, nullptr);
}
extern "C" nss_status _nss_windns_gethostbyaddr2_r(const void *addr, socklen_t addr_len, int family, hostent *result, char *buf, size_t buf_len, int *errno_p, int *h_errno_p, int32_t *ttl_p)
{
	auto impl_ret = gethostbyaddr_impl(std::span<const std::byte>(reinterpret_cast<const std::byte *>(addr), addr_len), family, result, std::span<char>(buf, buf_len), ttl_p);
	*errno_p = impl_ret.errno_;
	*h_errno_p = impl_ret.h_errno_;
	return impl_ret.func_ret;
}

extern "C" nss_status _nss_windns_gethostbyname_r(const char *name, hostent *result, char *buf, size_t buf_len, int *errno_p, int *h_errno_p)
{
	return _nss_windns_gethostbyname2_r(name, AF_INET, result, buf, buf_len, errno_p, h_errno_p);
}
extern "C" nss_status _nss_windns_gethostbyname2_r(const char *name, int family, hostent *result, char *buf, size_t buf_len, int *errno_p, int *h_errno_p)
{
	return _nss_windns_gethostbyname3_r(name, family, result, buf, buf_len, errno_p, h_errno_p, nullptr, nullptr);
}
extern "C" nss_status _nss_windns_gethostbyname3_r(const char *name, int family, hostent *result, char *buf, size_t buf_len, int *errno_p, int *h_errno_p, int32_t *ttl_p, char **canonp)
{
	auto impl_ret = gethostbyname_hostent(name, family, result, std::span<char>(buf, buf_len), ttl_p, canonp);
	*errno_p = impl_ret.errno_;
	*h_errno_p = impl_ret.h_errno_;
	return impl_ret.func_ret;
}
extern "C" nss_status _nss_windns_gethostbyname4_r(const char *name, gaih_addrtuple **pat, char *buf, size_t buf_len, int *errno_p, int *h_errno_p, int32_t *ttl_p)
{
	auto impl_ret = gethostbyname_addrtuple(name, pat, std::span<char>(buf, buf_len), ttl_p);
	*errno_p = impl_ret.errno_;
	*h_errno_p = impl_ret.h_errno_;
	return impl_ret.func_ret;
}
