#define NOMINMAX

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
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

#include <WinSock2.h>

namespace argentum {
	namespace {
		struct sentinel_int {
			std::int64_t value;

			sentinel_int() noexcept : value {std::numeric_limits<std::int64_t>::max()} {};
			sentinel_int(std::int64_t v) noexcept : value {v} {}
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
			stack_allocator(std::size_t capacity) : buffer(capacity) {}

			template <typename type, typename... pack_types>
			type* try_allocate(pack_types&&... pack) noexcept(new(std::declval<void*>())
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

		struct node : std::variant<list, dict, num, str> {};

		// Bencoding parser
		// How will memory management work for the parse nodes?
		// How often will we need to parse bencoding? It's not heavily involved in the peer protocol
		// Two stacks -> one grows from caller to callee, one from callee to caller
		// That way we can keep contiguous in-flight allocation, while still having persstent result allocation
		class bparser {
			using iterator = gsl::span<const char>::iterator;

		public:
			bparser() = default;
			bparser(gsl::span<const char> data) noexcept : end {data.end()}, pos {data.begin()} {}
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
		std::size_t get_message_size(gsl::span<const std::string_view> qname)
		{
			auto query_bytes = sizeof(dns_header);
			for (const auto label : qname) {
				const auto length = gsl::narrow<std::uint8_t>(label.size());
				query_bytes += length + 1;
			}

			query_bytes += sizeof(rr_type);
			query_bytes += sizeof(rr_class);

			return query_bytes;
		}

		struct buffer_writer {
			std::vector<char> buffer;
			std::size_t index;

			buffer_writer(std::size_t capacity) : buffer(capacity), index {} {}

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
			socket_handle(SOCKET sock) noexcept : sock {sock} {}
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
	else {
		std::cerr << "Unrecognized tool" << std::endl;
		return 1;
	}
}
