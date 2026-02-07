#include <algorithm>
#include <cctype>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <gsl/gsl>

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
		using dict = std::unordered_map<std::string_view, node>;

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
					value += c - '0';
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

			std::optional<dict> rule_dictionary() noexcept
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

			std::optional<node> rule_any() noexcept
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
	}
}

int main(int argc, char** argv)
{
	const gsl::span args {argv, gsl::narrow_cast<std::size_t>(argc)};
	if (argc != 2) {
		std::cerr << "Usage: argentum <file>" << std::endl;
		return 1;
	}

	const auto metainfo_buffer = argentum::load_file(args[1]);
	argentum::bparser parser {metainfo_buffer};
	const auto maybe_parsed = parser.try_decode();
	if (!maybe_parsed) {
		std::cerr << "Failed to parse metainfo file" << std::endl;
		return 1;
	}
}
