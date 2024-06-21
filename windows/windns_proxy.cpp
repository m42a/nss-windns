#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>

#include <cstring>

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <afunix.h>

using namespace std::literals;

struct raii_socket
{
	SOCKET s;
	static constexpr SOCKET invalid = INVALID_SOCKET;

	explicit raii_socket(SOCKET s) noexcept : s(s) {}
	raii_socket(raii_socket&& rs) noexcept : s(rs.s)
	{
		rs.s = invalid;
	}
	raii_socket& operator=(raii_socket&& rs) & noexcept
	{
		raii_socket tmp(std::move(rs));
		std::swap(s, tmp.s);
		return *this;
	}
	~raii_socket()
	{
		close();
	}

	void close()
	{
		if (s != invalid)
		{
			closesocket(s);
			s = invalid;
		}
	}
	operator SOCKET() noexcept
	{
		return s;
	}
};

bool debug_output = false;

static constexpr auto addr_prefix = "addr "sv;
static constexpr auto name_prefix = "name "sv;

static void send_response(raii_socket request_sock, std::string_view prefix, WSABUF data, int connection_num)
{
	WSABUF send_bufs[] = {
		{
			.len = static_cast<ULONG>(prefix.size()),
			.buf = const_cast<char*>(prefix.data())
		},
		data
	};
	DWORD bytes_sent;
	auto send_ret = WSASend(request_sock, send_bufs, std::extent_v<decltype(send_bufs)>, &bytes_sent, 0, nullptr, nullptr);
	if (send_ret == SOCKET_ERROR)
	{
		if (debug_output)
			std::cout << "Failed to send response to connection " << connection_num << '\n';
		return;
	}
	// TODO: Loop if the message tore
	return;
}

int recv_all(SOCKET s, char* buf, int buf_size)
{
	// We can't use MSG_WAITALL because Windows doesn't implement that correctly, so do it ourself
	int bytes_read = 0;
	while (bytes_read < buf_size)
	{
		auto recv_ret = recv(s, buf + bytes_read, buf_size - bytes_read, 0);
		if (recv_ret == SOCKET_ERROR)
			return SOCKET_ERROR;
		if (recv_ret == 0)
			break;
		bytes_read += recv_ret;
	}
	return bytes_read;
}

struct addrinfo_request_data
{
	OVERLAPPED o{};
	raii_socket request_sock;
	int connection_num;
	PADDRINFOEXW lookup_result = nullptr;

	addrinfo_request_data(raii_socket&& sock, int connection_num) noexcept : request_sock(std::move(sock)), connection_num(connection_num) {}
	~addrinfo_request_data()
	{
		if (lookup_result)
			FreeAddrInfoExW(lookup_result);
	}

	void on_completion_impl(DWORD err) noexcept
	{
		if (debug_output)
			std::cout << "GetAddrInfoExW completed for connection " << connection_num << " with status " << err << '\n';
		if (err != 0)
			return;
		// Remember previous addresses so we don't report duplicates
		std::unordered_set<std::string_view> addr_results;
		std::vector<char> response_buffer;
		for (auto info = lookup_result; info; info = info->ai_next)
		{
			if (info->ai_family == AF_INET)
			{
				auto addr = reinterpret_cast<const sockaddr_in*>(info->ai_addr);
				std::string_view addr_bytes(reinterpret_cast<const char*>(&addr->sin_addr), sizeof(addr->sin_addr));
				auto [iter, did_insert] = addr_results.insert(addr_bytes);
				if (did_insert)
				{
					response_buffer.push_back('4');
					response_buffer.insert(end(response_buffer), begin(addr_bytes), end(addr_bytes));
				}
			}
			else if (info->ai_family == AF_INET6)
			{
				auto addr = reinterpret_cast<const sockaddr_in6*>(info->ai_addr);
				std::string_view addr_bytes(reinterpret_cast<const char*>(&addr->sin6_addr), sizeof(addr->sin6_addr));
				auto [iter, did_insert] = addr_results.insert(addr_bytes);
				if (did_insert)
				{
					response_buffer.push_back('6');
					response_buffer.insert(end(response_buffer), begin(addr_bytes), end(addr_bytes));
				}

			}
		}
		if (!response_buffer.empty())
		{
			WSABUF response_data{
				.len = static_cast<ULONG>(response_buffer.size()),
				.buf = response_buffer.data()
			};
			send_response(std::move(request_sock), addr_prefix, response_data, connection_num);
		}
	}

	static void on_completion(DWORD err, DWORD, LPWSAOVERLAPPED o)
	{
		auto request_data_ptr = reinterpret_cast<addrinfo_request_data*>(o);
		request_data_ptr->on_completion_impl(err);
		delete request_data_ptr;
	}

	static void do_lookup(raii_socket&& request_sock, std::string_view name, int connection_num) noexcept
	{
		auto wide_name = [&]() -> std::wstring {
			std::wstring ret;
			auto required_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), name.size(), nullptr, 0);
			if (required_size == 0)
				return ret;
			ret.resize_and_overwrite(required_size, [&](wchar_t* buf, size_t buf_size) noexcept {
				return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), name.size(), buf, buf_size);
			});
			return ret;
		}();
		if (wide_name.empty())
		{
			if (debug_output)
				std::cout << "Failed to convert hostname " << name << " from connection " << connection_num << " to UTF-16\n";
			return;
		}
		std::cout << "Doing lookup of hostname " << name << " for connection " << connection_num << '\n';
		auto data_ptr = new addrinfo_request_data(std::move(request_sock), connection_num);
		auto gai_ret = GetAddrInfoExW(wide_name.data(), nullptr, NS_DNS, nullptr, nullptr, &data_ptr->lookup_result, nullptr, &data_ptr->o, &addrinfo_request_data::on_completion, nullptr);
		if (gai_ret != WSA_IO_PENDING)
		{
			if (debug_output)
				std::cout << "GetAddrInfoExW completed immediately for connection " << connection_num << '\n';

			data_ptr->on_completion_impl(gai_ret);
			delete data_ptr;
		}
		else
		{
			if (debug_output)
				std::cout << "GetAddrInfoExW is processing for connection " << connection_num << '\n';
		}
	}
};

static_assert(offsetof(addrinfo_request_data, o) == 0);

static void handle_request(raii_socket request_sock, int connection_num) noexcept
{
	if (debug_output)
		std::cout << "Handling request from connection " << connection_num << '\n';

	char recv_buf[4096];
	auto recv_ret = recv_all(request_sock, recv_buf, sizeof(recv_buf));
	if (recv_ret == SOCKET_ERROR)
	{
		if (debug_output)
			std::cout << "Failed to receive data from connection " << connection_num << '\n';
		return;
	}

	if (debug_output)
		std::cout << "Got " << recv_ret << " byte request from connection " << connection_num << '\n';

	if (recv_ret < 6)
	{
		if (debug_output)
			std::cout << "Request from connection " << connection_num << " was too short\n";
		return;
	}
	std::string_view data_type(recv_buf, 5);
	if (data_type == addr_prefix)
	{
		// 5-byte prefix + 1-byte type
		char* address_addr = recv_buf + 6;
		// There's no async version of getnameinfo, but these lookups shouldn't be frequent, so it's not worth pushing it to a different thread
		switch (recv_buf[5])
		{
		case '4':
			{
				if (recv_ret < 6 + sizeof(in_addr))
				{
					if (debug_output)
						std::cout << "Reverse-lookup ipv4 request from connection " << connection_num << " was too short (address was " << recv_ret - 6 << " bytes)\n";
					break;
				}
				sockaddr_in lookup_addr{
					.sin_family = AF_INET
				};
				std::memcpy(&lookup_addr.sin_addr, address_addr, sizeof(in_addr));
				char name_buf[NI_MAXHOST];
				if (debug_output)
				{
					char addr_str_buf[128];
					auto addr_ptr = inet_ntop(AF_INET, address_addr, addr_str_buf, sizeof(addr_str_buf));
					if (addr_ptr)
						std::cout << "Starting reverse-lookup on ipv4 address " << addr_ptr << " for connection " << connection_num << '\n';
				}
				auto gni_ret = getnameinfo(reinterpret_cast<const sockaddr*>(&lookup_addr), sizeof(lookup_addr), name_buf, sizeof(name_buf), nullptr, 0, NI_NAMEREQD);
				if (gni_ret != 0)
				{
					if (debug_output)
						std::cout << "Reverse-lookup ipv4 request from connection " << connection_num << " failed\n";
					break;
				}
				WSABUF response_data{
					.len = static_cast<ULONG>(strnlen(name_buf, sizeof(name_buf))),
						.buf = name_buf
				};
				if (debug_output)
					std::cout << "Reverse-lookup for connection " << connection_num << " succeeded with name " << name_buf << '\n';
				send_response(std::move(request_sock), name_prefix, response_data, connection_num);
				break;
			}
		case '6':
			{
				if (recv_ret < 6 + sizeof(in6_addr))
				{
					if (debug_output)
						std::cout << "Reverse-lookup ipv6 request from connection " << connection_num << " was too short (address was " << recv_ret - 6 << " bytes)\n";
					break;
				}
				sockaddr_in6 lookup_addr{
					.sin6_family = AF_INET6
				};
				std::memcpy(&lookup_addr.sin6_addr, address_addr, sizeof(in6_addr));
				char name_buf[NI_MAXHOST];
				if (debug_output)
				{
					char addr_str_buf[128];
					auto addr_ptr = inet_ntop(AF_INET6, address_addr, addr_str_buf, sizeof(addr_str_buf));
					if (addr_ptr)
						std::cout << "Starting reverse-lookup on ipv6 address " << addr_ptr << " for connection " << connection_num << '\n';
				}
				auto gni_ret = getnameinfo(reinterpret_cast<const sockaddr*>(&lookup_addr), sizeof(lookup_addr), name_buf, sizeof(name_buf), nullptr, 0, NI_NAMEREQD);
				if (gni_ret != 0)
				{
					if (debug_output)
						std::cout << "Reverse-lookup ipv6 request from connection " << connection_num << " failed\n";
					break;
				}
				WSABUF response_data{
					.len = static_cast<ULONG>(strnlen(name_buf, sizeof(name_buf))),
						.buf = name_buf
				};
				if (debug_output)
					std::cout << "Reverse-lookup for connection " << connection_num << " succeeded with name " << name_buf << '\n';
				send_response(std::move(request_sock), name_prefix, response_data, connection_num);
				break;
			}
		default:
			{
				if (debug_output)
					std::cout << "Reverse-lookup request from connection " << connection_num << " had unknown address type\n";
				break;
			}
		}
		return;
	}
	else if (data_type == name_prefix)
	{
		std::string_view name_str(recv_buf + 5, recv_ret - 5);
		addrinfo_request_data::do_lookup(std::move(request_sock), name_str, connection_num);
		return;
	}
	else
	{
		if (debug_output)
			std::cout << "Request from connection " << connection_num << " had an invalid type\n";
		return;
	}
}

bool alloc_console()
{
	bool got_console = AllocConsole();
	if (!got_console)
		return false;

	auto reopen_ret = freopen("CONIN$", "r", stdin);
	if (!reopen_ret)
		return false;
	std::cin.clear();
	reopen_ret = freopen("CONOUT$", "w", stdout);
	if (!reopen_ret)
		return false;
	std::cout.clear();
	reopen_ret = freopen("CONOUT$", "w", stderr);
	if (!reopen_ret)
		return false;
	std::cerr.clear();

	return true;
}

[[noreturn]] static void print_help()
{
	auto should_pause = alloc_console();
	std::cout << "Creates a socket that can resolve DNS queries. Used in tandem with the WinDNS nss library for glibc.\n"
		"Usage: WinDNS-Proxy.exe [--help] [--debug-output] C:\\path\\to\\socket\n"
		"\t--help          Display this help\n"
		"\t--debug-output  Show received requests\n"
		"\tsocket path     The socket to listen on\n";
	if (should_pause)
		std::cin.get();
	std::exit(0);
}

int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	auto wide_cmdline = GetCommandLineW();
	int num_args;
	auto cmd_args = CommandLineToArgvW(wide_cmdline, &num_args);
	if (!cmd_args)
	{
		std::cout << "Failed to parse command line\n";
		return 1;
	}

	std::wstring wide_socket_path;
	bool ignore_options = false;
	for (int i = 1; i < num_args; ++i)
	{
		std::wstring_view arg = cmd_args[i];
		if (!ignore_options && arg == L"--help"sv)
			print_help();
		else if (!ignore_options && arg == L"--debug-output"sv)
			debug_output = true;
		else if (!ignore_options && arg == L"--"sv)
			ignore_options = true;
		else if (wide_socket_path.empty())
			wide_socket_path = arg;
		else
			print_help();
	}

	LocalFree(cmd_args);

	if (wide_socket_path.empty())
		print_help();

	if (debug_output)
	{
		alloc_console();
		SetConsoleOutputCP(CP_UTF8); // for idn lookups
	}

	WSADATA wsa_data = { 0 };
	auto wsastartup_ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (wsastartup_ret != 0) {
		std::cout << "WSAStartup failed\n";
		return 2;
	}

	auto listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener == INVALID_SOCKET)
	{
		std::cout << "Failed to create socket\n";
		return 3;
	}

	sockaddr_un listen_addr{
		.sun_family = AF_UNIX
	};
	// The socket path must be utf-8, so convert it
	auto converted_path = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_socket_path.c_str(), wide_socket_path.size(), listen_addr.sun_path, (int)sizeof(listen_addr.sun_path), nullptr, nullptr);
	if (converted_path == 0)
	{
		std::cout << "Failed to convert socket path\n";
		return 4;
	}

	// In case the socket is left over from the last run, delete it. Ignore the return value, since binding will fail if the delete fails
	DeleteFileW(wide_socket_path.c_str());

	// Bind the socket to the path.
	auto bind_ret = bind(listener, reinterpret_cast<struct sockaddr*>(&listen_addr), sizeof(listen_addr));
	if (bind_ret == SOCKET_ERROR) {
		std::cout << "Failed to bind to socket\n";
		return 5;
	}

	if (debug_output)
		std::cout << "Bound socket to path " << std::string_view(listen_addr.sun_path, converted_path) << '\n';

	// Open the socket with FILE_FLAG_DELETE_ON_CLOSE. This way, the socket will be removed even if the program crashes or is killed.
	auto socket_closer = CreateFileW(wide_socket_path.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (socket_closer == INVALID_HANDLE_VALUE) {
		std::cout << "Auto-deletion not enabled for socket\n";
		// This is unfortunate, but not fatal
	}

	// Listen to start accepting connections.
	auto listen_ret = listen(listener, SOMAXCONN);
	if (listen_ret == SOCKET_ERROR) {
		std::cout << "Listening on socket failed\n";
		return 6;
	}

	if (debug_output)
		std::cout << "Listening for requests\n";

	bool accepting = false;
	int connection_num = 0;
	while (true)
	{
		auto request_sock = accept(listener, nullptr, nullptr);
		if (request_sock == INVALID_SOCKET)
		{
			std::cout << "Accepting connection on socket failed\n";
			return 7;
		}
		DWORD timeout = 1000;
		setsockopt(request_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
		setsockopt(request_sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
		handle_request(raii_socket{ request_sock }, connection_num++);
	}
}
