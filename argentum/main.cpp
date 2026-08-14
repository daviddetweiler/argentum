#define NOMINMAX

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <ostream>
#include <random>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <gsl/gsl>

#include "tls_1_3.h"

#include <tdh.h>

namespace argentum {
	namespace {
		struct sentinel_int {
			std::int64_t value;

			sentinel_int() noexcept : value {std::numeric_limits<std::int64_t>::max()} { };
			sentinel_int(std::int64_t v) noexcept : value {v} { }
			operator std::int64_t() const noexcept { return value; }
			operator bool() const noexcept { return value != std::numeric_limits<std::int64_t>::max(); }
		};

		auto load_file(gsl::czstring filename)
		{
			std::ifstream file {filename, std::ifstream::binary | std::ifstream::ate};
			file.exceptions(file.badbit | file.failbit);
			const auto size = file.tellg();
			std::vector<char> buffer(size);
			file.seekg(0);
			file.read(buffer.data(), size);
			return buffer;
		}

		class stack_allocator {
		public:
			stack_allocator() = default;
			stack_allocator(std::size_t capacity) : buffer(capacity) { }

			template <typename type, typename... pack_types>
			type* try_allocate(pack_types&&... pack) noexcept(new (std::declval<void*>())
																  type {std::declval<decltype(pack)>()})
			{
				const auto attempt = try_many<type>(1);
				if (!attempt.size())
					return nullptr;

				return &attempt.front();
			}

			template <typename type>
			gsl::span<type> try_many(std::size_t count)
			{
				Expects(count > 0);

				static_assert(std::is_trivially_destructible_v<type>, "type must be trivially destructible");

				auto space = buffer.size() - top;
				void* ptr = &buffer.at(top);
				const auto result = std::align(alignof(type), sizeof(type) * count, ptr, space);
				if (!result)
					return {};

				top = buffer.size() - space - sizeof(type);

				return {new (result) type {}, count};
			}

			auto here() noexcept { return top; }

			void reset(std::size_t marker) noexcept
			{
				Expects(marker <= buffer.size());
				top = marker;
			}

		private:
			// MUST not resize this, ever
			std::vector<char> buffer {};
			std::size_t top {};
		};

		struct node;

		using list = std::vector<node>;
		using str = std::string_view;
		using num = std::int64_t;
		using dict = std::map<std::string_view, node>;

		struct node : std::variant<list, dict, num, str> { };

		// Bencoding parser
		// How will memory management work for the parse nodes?
		// How often will we need to parse bencoding? It's not heavily involved in the peer protocol
		// Two stacks -> one grows from caller to callee, one from callee to caller
		// That way we can keep contiguous in-flight allocation, while still having persstent result allocation
		class bparser {
			using iterator = gsl::span<const char>::iterator;

		public:
			bparser() = default;
			bparser(gsl::span<const char> data) noexcept : end {data.end()}, pos {data.begin()} { }
			auto try_decode() noexcept { return any(); }

		private:
			iterator end {};
			iterator pos {};

			template <typename type, std::optional<type> (bparser::*parse_rule)()>
			auto attempt() noexcept
			{
				const auto backup = pos;
				const auto result = (this->*parse_rule)();
				if (!result)
					pos = backup;

				return result;
			}

			char peek() const noexcept { return pos != end ? *pos : '\0'; }

			template <char c>
			std::optional<std::monostate> rule_symbol() noexcept
			{
				if (peek() == c) {
					++pos;
					return std::monostate {};
				}

				return std::nullopt;
			}

			template <char c>
			auto symbol() noexcept
			{
				return attempt<std::monostate, &bparser::rule_symbol<c>>();
			}

			std::optional<num> rule_digits() noexcept
			{
				auto first_digit = true;
				std::uint64_t value {};
				while (true) {
					const auto c = *pos;
					if (!std::isdigit(c))
						break;

					first_digit = false;
					++pos;

					const auto old = value;
					value *= 10;
					value += static_cast<num>(c) - '0';
					if (value < old)
						return std::nullopt;
				}

				if (first_digit)
					return std::nullopt;

				return gsl::narrow<std::int64_t>(value);
			}

			auto digits() noexcept { return attempt<num, &bparser::rule_digits>(); }

			std::optional<num> rule_number() noexcept
			{
				if (!symbol<'i'>())
					return {};

				const auto leading_zero = peek() == '0';
				const auto is_negative = symbol<'-'>();
				auto maybe_value = digits();
				if (!maybe_value)
					return std::nullopt;

				auto& value = *maybe_value;
				if (value == 0 && is_negative)
					return std::nullopt;

				if (value != 0 && leading_zero)
					return std::nullopt;

				if (!symbol<'e'>())
					return std::nullopt;

				if (is_negative)
					value = -value;

				return maybe_value;
			}

			auto number() noexcept { return attempt<num, &bparser::rule_number>(); }

			std::optional<list> rule_list() noexcept
			{
				if (!symbol<'l'>())
					return std::nullopt;

				argentum::list nodes {};
				while (true) {
					auto maybe_node = any();
					if (!maybe_node)
						break;

					nodes.emplace_back(std::move(*maybe_node));
				}

				if (!symbol<'e'>())
					return std::nullopt;

				return std::move(nodes);
			}

			auto list() noexcept { return attempt<argentum::list, &bparser::rule_list>(); }

			std::optional<std::string_view> rule_string() noexcept
			{
				const auto maybe_length = digits();
				if (!maybe_length)
					return std::nullopt;

				const auto length = *maybe_length;
				if (length < 0)
					return std::nullopt;

				if (!symbol<':'>())
					return std::nullopt;

				if (end - pos < length)
					return std::nullopt;

				const auto start = &*pos;
				pos += length;

				return std::string_view {start, gsl::narrow<std::size_t>(length)};
			}

			auto string() noexcept { return attempt<std::string_view, &bparser::rule_string>(); }

			std::optional<dict> rule_dictionary()
			{
				if (!symbol<'d'>())
					return std::nullopt;

				dict nodes {};
				std::string_view last_key {};
				auto is_first = true;
				while (true) {
					const auto maybe_key = string();
					if (!maybe_key)
						break;

					const auto key = *maybe_key;
					if (!is_first && last_key >= key)
						return std::nullopt;

					last_key = key;
					is_first = false;

					auto maybe_node = any();
					if (!maybe_node)
						return std::nullopt;

					nodes.emplace(key, std::move(*maybe_node));
				}

				if (!symbol<'e'>())
					return std::nullopt;

				return std::move(nodes);
			}

			auto dictionary() noexcept { return attempt<dict, &bparser::rule_dictionary>(); }

			std::optional<node> rule_any()
			{
				auto maybe_list = list();
				if (maybe_list)
					return std::make_optional<node>(std::move(*maybe_list));

				auto maybe_dict = dictionary();
				if (maybe_dict)
					return std::make_optional<node>(std::move(*maybe_dict));

				auto maybe_num = number();
				if (maybe_num)
					return std::make_optional<node>(std::move(*maybe_num));

				auto maybe_str = string();
				if (maybe_str)
					return std::make_optional<node>(std::move(*maybe_str));

				return std::nullopt;
			}

			std::optional<node> any() noexcept { return attempt<node, &bparser::rule_any>(); }
		};

		void dump(std::ostream& stream, const node& n);

		void dump(std::ostream& stream, const list& l)
		{
			stream << '[';
			auto is_first = true;
			for (const auto& n : l) {
				if (!is_first)
					stream << ',';

				is_first = false;
				dump(stream, n);
			}

			stream << ']';
		}

		void dump(std::ostream& stream, const str& s)
		{
			stream << '"';
			for (const unsigned char ch : s) {
				if (ch == '"' || ch == '\\')
					stream << '\\' << ch;
				else if (std::isprint(ch))
					stream << ch;
				else
					stream << std::format("\\x{:2x}", ch);
			}

			stream << '"';
		}

		void dump(std::ostream& stream, const dict& d)
		{
			stream << '{';
			auto is_first = true;
			for (const auto& item : d) {
				if (!is_first)
					stream << ',';

				is_first = false;
				dump(stream, item.first);
				stream << ':';
				dump(stream, item.second);
			}

			stream << '}';
		}

		void dump(std::ostream& stream, const num& n) { stream << n; }

		void dump(std::ostream& stream, const node& n)
		{
			// Wait... how tf does passing a generic lambda as an argument work?
			// The implied templating happens only on its call operator, that's how
			const auto visitor = [&stream](auto&& obj) {
				using type = std::decay_t<decltype(obj)>;
				if constexpr (std::is_same_v<type, num>)
					dump(stream, obj);
				else if constexpr (std::is_same_v<type, list>)
					dump(stream, obj);
				else if constexpr (std::is_same_v<type, dict>)
					dump(stream, obj);
				else if constexpr (std::is_same_v<type, str>)
					dump(stream, obj);
				else if constexpr (true)
					static_assert(false);
			};

			std::visit(visitor, n);
		}

		int dump_bencoding(gsl::span<gsl::zstring> args)
		{
			if (args.size() != 4) {
				std::cerr << "Usage: argentum bencoding <file> <dump-file>" << std::endl;
				return 1;
			}

			const auto metainfo_buffer = load_file(args[2]);
			bparser parser {metainfo_buffer};
			const auto maybe_parsed = parser.try_decode();
			if (!maybe_parsed) {
				std::cerr << "Failed to parse metainfo file" << std::endl;
				return 1;
			}

			std::ofstream dumpfile {args[3]};
			dumpfile.exceptions(dumpfile.badbit | dumpfile.failbit);
			dump(dumpfile, *maybe_parsed);

			return 0;
		}

		template <typename type>
		auto pun(const void* ptr) noexcept
		{
			static_assert(std::is_trivial_v<type>);
			return static_cast<type*>(ptr);
		}

		enum class rr_type : std::uint16_t {
			a = 1,
			ns = 2,
			cname = 5,
			soa = 6,
			ptr = 12,
		};

		enum class rr_class : std::uint16_t {
			in = 1,
		};

		enum class dns_op : std::uint8_t {

		};

		enum class dns_rcode : std::uint8_t {
			none = 0,
			format = 1,
			server = 2,
			name = 3,
			unimplemented = 4,
			refused = 5,
		};

		struct dns_flags {
			bool is_response : 1;
			dns_op opcode : 4;
			bool is_authority : 1;
			bool is_truncated : 1;
			bool is_rec_wanted : 1;
			bool is_rec_offered : 1;
			std::uint8_t reserved : 3;
			dns_rcode rcode : 4;
		};

		struct dns_header {
			std::uint16_t id;
			dns_flags flags;
			std::uint16_t qdcount;
			std::uint16_t ancount;
			std::uint16_t nscount;
			std::uint16_t arcount;
		};

		static_assert(sizeof(dns_flags) == 2);
		static_assert(offsetof(dns_header, qdcount) == 4);

		struct dns_question {
			gsl::span<std::string_view> qname;
			rr_type qtype;
			rr_class qclass;
		};

		// Assuming you have only one question, of course...
		constexpr std::size_t get_message_size(gsl::span<const std::string_view> qname)
		{
			auto query_bytes = sizeof(dns_header);
			for (const auto label : qname) {
				const auto length = gsl::narrow<std::uint8_t>(label.size());
				query_bytes += length + 1ull;
			}

			query_bytes += sizeof(rr_type);
			query_bytes += sizeof(rr_class);

			return query_bytes;
		}

		struct buffer_writer {
			std::vector<char> buffer;
			std::size_t index;

			buffer_writer(std::size_t capacity) : buffer(capacity), index {} { }

			template <typename type, typename... pack_types>
			[[gsl::suppress(r.3)]]
			auto emplace(pack_types&&... pack)
			{
				Expects(buffer.size() - index >= sizeof(type));
				const auto ptr = new (&gsl::at(buffer, index)) type {std::forward<pack_types>(pack)...};
				index += sizeof(type);
				return ptr;
			}

			auto domain(gsl::span<const std::string_view> name)
			{
				for (const auto label : name) {
					Ensures(buffer.size() - index >= 1);
					const auto length = gsl::narrow<std::uint8_t>(label.size());
					emplace<std::uint8_t>(length);
					if (length) {
						Ensures(buffer.size() - index >= length);
						std::memcpy(&gsl::at(buffer, index), label.data(), length);
						index += length;
					}
				}
			}

			auto size() const noexcept { return buffer.size(); }
			auto data() const noexcept { return buffer.data(); }

			void check() const noexcept { Expects(index == buffer.size()); }
		};

		class socket_handle {
		public:
			socket_handle(SOCKET sock) noexcept : sock {sock} { }
			socket_handle(socket_handle&) = default;
			socket_handle(socket_handle&&) = default;
			socket_handle& operator=(socket_handle&) = default;
			socket_handle& operator=(socket_handle&&) = default;

			~socket_handle() noexcept
			{
				if (sock != INVALID_SOCKET)
					closesocket(sock);
			}

			operator SOCKET() const noexcept { return sock; }

		private:
			SOCKET sock {};
		};

		struct record {
			std::shared_ptr<record*> next;
			std::chrono::system_clock::time_point expiry;
			gsl::span<const char> data;
		};

		class query_cache {
			// Doesn't need to always own.
			// Why not just have interned labels and interned domain names?
			using key = std::pair<std::vector<std::string_view>, rr_type>;

		public:
			query_cache() = default;

			query_cache(std::size_t power) : query_cache {}
			{
				Expects(power < 32);
				const auto size = 1ull << power;
				mask = size - 1;
				keys.resize(size);
				values.resize(size);
			}

			std::shared_ptr<record*> operator[](const key& query) noexcept
			{
				const auto index = hash(query);
				if (gsl::at(keys, index) != query)
					return {};

				return gsl::at(values, index);
			}

			std::shared_ptr<record*>& insert_at(key query) noexcept
			{
				const auto index = hash(query);
				auto& key = gsl::at(keys, index);
				auto& value = gsl::at(values, index);
				// NOT THREAD SAFE
				if (key != query) {
					key = query;
					value.reset();
				}

				return value;
			}

		private:
			std::vector<key> keys {};
			std::vector<std::shared_ptr<record*>> values {};
			std::size_t mask {};

			std::uint32_t hash(const key& query) noexcept
			{
				std::uint32_t crc32 {0xffffffff};
				crc32 = gsl::narrow_cast<std::uint32_t>(_mm_crc32_u64(crc32, query.first.size()));
				for (auto label : query.first) {
					crc32 = gsl::narrow_cast<std::uint32_t>(_mm_crc32_u64(crc32, label.size()));
					for (auto ch : label) {
						crc32 = _mm_crc32_u8(crc32, ch);
					}
				}

				crc32 = _mm_crc32_u16(crc32, static_cast<std::uint16_t>(query.second));

				return crc32 & mask;
			}
		};

		// Implied IN QCLASS (i.e. CLASS 1)
		// In future, we'd want to batch multiple queries to the same server into the same message
		// ... modulo truncation, of course. Chief reason to avoid TCP is to avoid the connection setup / teardown
		// overhead
		bool send_query(SOCKET sock, const sockaddr_in& addr, gsl::span<const std::string_view> qname, rr_type qtype)
		{
			Expects(qname.back().size() == 0);
			const auto query_bytes = get_message_size(qname);
			buffer_writer writer {query_bytes};

			std::random_device device {};
			std::uniform_int_distribution<std::uint16_t> dist {};
			const auto header = writer.emplace<dns_header>();
			header->id = htons(dist(device));
			header->qdcount = htons(1);
			writer.domain(qname);
			writer.emplace<std::uint16_t>(htons(static_cast<std::uint16_t>(qtype)));
			writer.emplace<std::uint16_t>(htons(static_cast<std::uint16_t>(rr_class::in)));

			const auto result = sendto(
				sock,
				writer.data(),
				gsl::narrow<int>(writer.size()),
				0,
				pun<const sockaddr>(&addr),
				sizeof(addr));

			return result != SOCKET_ERROR;
		}

		// How to maintain the NS records of the root zone?
		// Or really, the authoritative records of any zone root?
		int resolve_dns(gsl::span<gsl::zstring> args)
		{
			if (args.size() != 3) {
				std::cerr << "Usage: argentum dns <domain>" << std::endl;
				return 1;
			}

			const std::string_view fqdn {args[2]};
			std::vector<std::string_view> domain {};
			auto start = fqdn.begin();
			const auto end = fqdn.end();
			auto empty_labels = 0;
			for (auto iter = start; iter != end; ++iter) {
				if (*iter == '.') {
					const std::string_view label {&*start, gsl::narrow_cast<std::size_t>(iter - start)};
					if (label.empty())
						++empty_labels;

					domain.emplace_back(label);
					start = iter;
					++start;
				}
			}

			if (start != end)
				domain.emplace_back(&*start, end - start);

			if (empty_labels == 0)
				domain.emplace_back();
			else if (empty_labels > 1)
				std::cerr << "Not a valid FQDN" << std::endl;

			for (auto label : domain)
				std::cout << "> " << label << '\n';

			std::cout << std::endl;

			WSADATA wsa_data {};
			if (WSAStartup(MAKEWORD(2, 2), &wsa_data))
				return -1;

			const auto cleanup = gsl::finally([]() noexcept { WSACleanup(); });
			const socket_handle sock {socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
			if (sock == INVALID_SOCKET)
				return -1;

			sockaddr_in address {};
			address.sin_family = AF_INET;
			// 198.41.0.4 (a.root-servers.net)
			address.sin_addr.S_un.S_un_b.s_b1 = 198;
			address.sin_addr.S_un.S_un_b.s_b2 = 41;
			address.sin_addr.S_un.S_un_b.s_b3 = 0;
			address.sin_addr.S_un.S_un_b.s_b4 = 4;
			address.sin_port = htons(53);

			if (!send_query(sock, address, domain, rr_type::ns)) {
				std::cerr << "Failed to send DNS query" << std::endl;
				return -1;
			}

			return 0;
		}

		int trace_tls(gsl::span<gsl::zstring> args)
		{
			if (args.size() < 3) {
				std::cerr << "Usage: argentum tls <hostname> [<port>]" << std::endl;
				return 1;
			}

			const auto port = args.size() < 4 ? "443" : args[3];
			winsock2 ws2 {{}};

			ADDRINFOA hints {};
			hints.ai_family = AF_UNSPEC;
			ADDRINFOA* result {};
			if (const auto err = getaddrinfo(args[2], port, &hints, &result); err) {
				std::cerr << "[-] Bad getaddrinfo (" << err << ")" << std::endl;
				return 1;
			}

			if (!result) {
				std::cerr << "[-] No results from DNS" << std::endl;
				return 1;
			}

			const auto free_info = gsl::finally([result]() noexcept { freeaddrinfo(result); });
			const auto sock = ws2.socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP);
			if (!sock.is_valid()) {
				std::cerr << "[-] Bad socket (" << ws2.error() << ")" << std::endl;
				return 1;
			}

			if (!sock.try_connect(result->ai_addr, gsl::narrow<int>(result->ai_addrlen))) {
				std::cerr << "[-] Bad connect (" << ws2.error() << ")" << std::endl;
				return 1;
			}

			if (sock.send("oh look some test garbage") < 0) {
				std::cerr << "[-] Did not send test message (" << ws2.error() << ")" << std::endl;
				return 1;
			}

			if (!sock.try_shutdown()) {
				std::cerr << "[-] Did not shut down gracefully" << std::endl;
				return 1;
			}

			return 0;
		}

		void dump32(gsl::span<const std::uint8_t> data)
		{
			for (auto i = 0; i < data.size(); ++i) {
				std::cout << std::format("{:02x}", gsl::at(data, i));
				if (i % 4 == 3)
					std::cout << ' ';
			}
		}

		template <typename type, std::size_t extent>
		gsl::span<const unsigned char> as_uchars(gsl::span<type, extent> span)
		{
			return {to_uint8_tp(span.data()), span.size_bytes()};
		}

		int sha256_hash(gsl::span<gsl::zstring> args)
		{
			if (args.size() < 3) {
				std::cerr << "Usage: argentum sha256 <filename>" << std::endl;
				return 1;
			}

			const auto blob = load_file(args[2]);
			std::array<std::uint8_t, 32> d {};
			sha256::stomach digester {};
			digester.init();
			digester.append(gsl::span {to_uint8_tp(blob.data()), blob.size()});
			digester.complete(d);
			dump32(d);

			return 0;
		}

		[[gsl::suppress("gsl.view")]]
		int aes256_transcode(gsl::span<gsl::zstring> args)
		{
			if (args.size() < 5) {
				std::cerr << "Usage: argentum aes256-ctr <keyfile> <in> <out>" << std::endl;
				return 1;
			}

			using cipher = rijndael::aes256;

			const auto keyfile = load_file(args[2]);
			std::array<std::uint8_t, cipher::key_size> key {};
			sha256::stomach digester {};
			digester.init();
			digester.append(as_uchars(gsl::span {keyfile}));
			digester.complete(key);
			std::cerr << "Using key: ";
			dump32(key);
			std::cerr << std::endl;

			auto source = load_file(args[3]);
			const rijndael::constant_table constants {};
			const cipher transcoder {constants, key};

			std::array<std::uint8_t, cipher::block_size> scratch {};
			const auto streamlen = source.size();
			for (std::uint64_t streampos {}, block_id {}; streampos < streamlen; streampos += sizeof(std::uint64_t)) {
				static_assert(cipher::block_size % sizeof(std::uint64_t) == 0);
				const auto block_offset = streampos % cipher::block_size;
				if (block_offset == 0) {
					std::memcpy(scratch.data(), &block_id, sizeof(block_id));
					transcoder.encrypt(constants, scratch);
					++block_id;
				}

				std::uint64_t a;
				std::memcpy(&a, std::next(scratch.data(), block_offset), sizeof(a));

				const auto stream_ptr = std::next(source.data(), streampos);
				std::uint64_t b;
				std::memcpy(&b, stream_ptr, sizeof(b));

				a ^= b;
				std::memcpy(stream_ptr, &a, std::min(sizeof(a), streamlen - streampos));
			}

			std::ofstream outfile {args[4], std::ofstream::binary};
			outfile.exceptions(outfile.badbit | outfile.failbit);
			outfile.write(source.data(), source.size());

			return 0;
		}

		std::wostream& operator<<(std::wostream& out, const GUID& guid)
		{
			out << std::format(
				L"{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
				guid.Data1,
				guid.Data2,
				guid.Data3,
				guid.Data4[0],
				guid.Data4[1],
				guid.Data4[2],
				guid.Data4[3],
				guid.Data4[4],
				guid.Data4[5],
				guid.Data4[6],
				guid.Data4[7]);

			return out;
		}

		template <typename alignment_type>
		struct aligned_array_deleter {
			static constexpr std::align_val_t alignment {alignof(alignment_type)};
			void operator()(void* ptr) const noexcept { ::operator delete[](ptr, alignment); }
		};

		template <typename alignment_type>
		using aligned_storage = std::unique_ptr<std::byte, aligned_array_deleter<alignment_type>>;

		template <typename alignment_type>
		auto make_aligned_storage(std::size_t size)
		{
			constexpr std::align_val_t alignment {alignof(alignment_type)};
			return aligned_storage<alignment_type> {static_cast<std::byte*>(::operator new[](size, alignment))};
		}

		[[gsl::suppress("r.3")]] [[gsl::suppress("r.3")]] [[gsl::suppress("r.5")]] [[gsl::suppress("bounds.3")]]
		int events(gsl::span<gsl::zstring>)
		{
			PROVIDER_ENUMERATION_INFO* info_ptr {};
			ULONG buflen {};
			aligned_storage<PROVIDER_ENUMERATION_INFO> buffer {};

			for (auto n = 6; n < 24; ++n) {
				buflen = 1ull << n;
				buffer = make_aligned_storage<PROVIDER_ENUMERATION_INFO>(buflen);
				void* const bufptr = buffer.get();
				info_ptr = static_cast<PROVIDER_ENUMERATION_INFO*>(bufptr);
				const auto err = TdhEnumerateProviders(info_ptr, &buflen);
				if (err == ERROR_SUCCESS)
					break;

				if (err != ERROR_INSUFFICIENT_BUFFER) {
					std::cerr << "[-] TdhEnumerateProviders(): " << err << std::endl;
					return 1;
				}
			}

			if (!buffer) {
				std::cerr << "[-] Exceeded maximum buffer size" << std::endl;
				return 1;
			}

			// https://eel.is/c++draft/intro.object#note-3
			// and https://eel.is/c++draft/basic.life#2.2
			// Roughly, `info_ptr` ceases to be valid as soon as `records` is acccessed, since the new array object
			// partially overlaps the old struct and is not a subobject.
			// Which is fine. It's not clear to me if the lifetime of `info_ptr` ends the lifetime of the containing
			// unsigged char array implicitly returned by operator new[], or just those unsigned chars it occupies.
			// The assumed rules:
			// - new[] returns an unsigned char array
			// - Subsequent pointer casts to implicit-creation types allows their lifetimes to start without issue, with
			// the expected object representation
			// - Any time we implicitly start lifetime, it ends the lifetime of overlapping implicit-lifetime types (and
			// invalidates their pointers)
			// - End of lifetime of these types does not disturb object representation
			// - Pointer arithmetic on the underlying unsigned char array is always defined
			// Per https://timsong-cpp.github.io/cppwp/n4861/basic.memobj#intro.object-4.2, the lifetime of the unsigned
			// char array is not ended by the objects it stores
			// Unfortunately, I think we have the following problem: once the info_ptr object ends its lifetime, the
			// implicit creation of the records array leaves the elements with an indeterminate value, and reading from
			// them is still UB.
			// According to https://eel.is/c++draft/basic#stc.general-2, the implicitly created objects are of dynamic
			// storage duration, and therefore, https://eel.is/c++draft/basic#indet-1.1 implies that the bytes of the
			// underlying storage are formally considered to have indeterminate values, and it is UB to access the
			// object without first overwriting it.
			// My question is: does memmove succeed in producing the desired effect?
			// According to https://eel.is/c++draft/c.strings#cstring.syn-3, std::memmove implicitly creates objects in
			// the destination Then the semantics would be of implicitly creating an object with storage of
			// indeterminate values, but _after_ the object representation has been "moved out of the way?" Yes,
			// according to the same note.
			const auto n_providers = info_ptr->NumberOfProviders;
			void* const records_ptr {
				std::next(buffer.get(), offsetof(PROVIDER_ENUMERATION_INFO, TraceProviderInfoArray))};

			// This has the effect of properly starting the lifetime of an initialized array here, but it simultaneously
			// ending the lifetime of info_ptr's referent. This is needed because the array partially overlaps info_ptr,
			// and so while the former's implicit creation and initialization is assumed to occur in the API call, we
			// are now responsible for properly starting the lifetime and performing initialization for the new array
			const gsl::span records {
				static_cast<const TRACE_PROVIDER_INFO*>(
					std::memmove(records_ptr, records_ptr, sizeof(TRACE_PROVIDER_INFO) * n_providers)),
				n_providers,
			};

			std::cerr << "[+] Retrieved " << records.size() << " provider records" << std::endl;

			std::wofstream dump {"providers.json"};
			dump.exceptions(dump.badbit | dump.failbit);
			dump << "[";
			auto is_first = true;
			for (const auto& record : records) {
				const std::wstring_view name {pun<const wchar_t>(std::next(buffer.get(), record.ProviderNameOffset))};

				if (!is_first)
					dump << ",";

				is_first = false;
				dump << "{";
				dump << "\"name\": \"" << name << "\",";
				dump << "\"guid\": \"" << record.ProviderGuid << "\",";
				dump << "\"schema\": \"" << (record.SchemaSource ? "Windows MOF" : "XML") << "\"";
				dump << "}";
			}

			dump << "]";

			// At this point we want to use TdhEnumerateManifestProviderEvents to load up the events they each declare

			return 0;
		}
	}
}

int main(int argc, char** argv)
{
	const gsl::span args {argv, gsl::narrow_cast<std::size_t>(argc)};
	const std::string_view tool {argc >= 2 ? args[1] : ""};
	if (tool == "bencoding")
		return argentum::dump_bencoding(args);
	else if (tool == "dns")
		return argentum::resolve_dns(args);
	else if (tool == "tls")
		return argentum::trace_tls(args);
	else if (tool == "sha256")
		return argentum::sha256_hash(args);
	else if (tool == "aes256-ctr")
		return argentum::aes256_transcode(args);
	else if (tool == "events")
		return argentum::events(args);
	else {
		std::cerr << "Unrecognized tool" << std::endl;
		return 1;
	}
}
