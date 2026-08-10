#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iostream>

#include <gsl/gsl>

#include <WinSock2.h>

#include <WS2tcpip.h>

namespace argentum {

	class ws2_socket {
	public:
		ws2_socket() = default;

		ws2_socket(SOCKET sock) noexcept : sock {sock} {}
		ws2_socket(ws2_socket&) = delete;
		ws2_socket(ws2_socket&& other) noexcept : sock {other.sock} { other.sock = INVALID_SOCKET; };
		ws2_socket& operator=(ws2_socket&) = delete;

		ws2_socket& operator=(ws2_socket&& other) noexcept
		{
			sock = other.sock;
			other.sock = INVALID_SOCKET;
		}

		~ws2_socket() noexcept
		{
			if (sock != INVALID_SOCKET)
				closesocket(sock);
		}

		bool is_valid() const noexcept { return sock != INVALID_SOCKET; }

		SOCKET get() const noexcept { return sock; }

		bool try_shutdown() const
		{
			if (shutdown(sock, SD_SEND) == SOCKET_ERROR) {
				std::cerr << "[-] Bad shutdown (" << WSAGetLastError() << ")" << std::endl;
				return false;
			}

			while (true) {
				std::array<char, 128> buffer {};
				const auto flushed = recv(buffer);
				if (flushed > 0)
					std::cerr << "[*] Flushed " << flushed << " bytes" << std::endl;
				else if (flushed < 0) {
					std::cerr << "[-] Bad recv (" << WSAGetLastError() << ")" << std::endl;
					return false;
				}
				else {
					std::cerr << "[+] Flushed socket" << std::endl;
					return true;
				}
			}
		}

		bool try_connect(const sockaddr* addr, std::size_t addrlen) const
		{
			return connect(sock, addr, gsl::narrow<int>(addrlen)) != SOCKET_ERROR;
		}

		int recv(gsl::span<char> buffer) const
		{
			return ::recv(sock, buffer.data(), gsl::narrow<int>(buffer.size()), 0);
		}

		int send(gsl::span<const char> buffer) const
		{
			return ::send(sock, buffer.data(), gsl::narrow<int>(buffer.size()), 0);
		}

	private:
		SOCKET sock {INVALID_SOCKET};
	};

	class winsock2 {
	public:
		struct tag {};

		winsock2() = default;

		winsock2(tag) : winsock2 {}
		{
			if (WSAStartup(MAKEWORD(2, 2), &wsa_data))
				throw std::runtime_error {std::format("WSAStartup(): {}", WSAGetLastError())};

			initialized = true;
		}

		winsock2(winsock2&) = delete;

		winsock2(winsock2&& other) noexcept : wsa_data {other.wsa_data}, initialized {true}
		{
			other.initialized = false;
		}

		winsock2& operator=(winsock2&) = delete;

		winsock2& operator=(winsock2&& other) noexcept
		{
			Expects(!initialized);
			wsa_data = other.wsa_data;
			initialized = true;
		}

		~winsock2() noexcept
		{
			if (initialized)
				WSACleanup();
		}

		ws2_socket socket(int af, int type, int proto) const noexcept { return {::socket(af, type, proto)}; }

		auto error() const noexcept { return WSAGetLastError(); }

	private:
		WSADATA wsa_data {};
		bool initialized {};
	};

	enum class handshake_type {
		client_hello = 1,
		server_hello = 2,
		new_session_ticket = 4,
		end_of_early_data = 5,
		encrypted_extensions = 8,
		certificate = 11,
		certificate_request = 13,
		certificate_verify = 15,
		finished = 20,
		key_update = 24,
		message_hash = 254,
	};

	template <std::size_t capacity>
	class serializer {
	public:
		serializer(const ws2_socket& sock) : sock {sock}, buffer {} {}

	private:
		const ws2_socket& sock {};
		std::array<char, capacity> buffer {};
	};

	/*
		Logically, the client_hello is structured like so:

		uint16	ProtocolVersion;
		opaque	Random[32];
		uint8	CipherSuite[2];

		struct {
			ProtocolVersion legacy_version = 0x0303;
			Random random; // Must be CSPRNG output
			opaque legacy_session_id<0..32>;
			CipherSuite cipher_suites<2..2^16-2>; // I.e. it must present at least two choices
			opaque legacy_compression_methods<1..2^8-1>;
			Extension extensions<8..2^16-1>;
		} ClientHello;

		If a client declares TLS 1.3 in its hello, but sends anything other than the null compression method, the server
	    is required to reject it. However, if a client declares 1.2, and the server does not intend to reject it, it
		must treat this field as defined in 1.2.
	*/

	/*
		Minimum support needs to be:
		- RSA signatures
		- Elliptic curve signatures and key exchange
		- SHA256 hashing
		- AES-GCM encryption
	*/

	namespace sha256 {
		using digest = gsl::span<char, 256 / 8>;

		void hash(digest d, gsl::span<const char> content);
	}
}
