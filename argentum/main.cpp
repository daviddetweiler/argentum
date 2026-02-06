#include <cctype>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <string_view>
#include <utility>
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
				static_assert(std::is_trivially_destructible_v<type>, "type must be trivially destructible");

				auto space = buffer.size() - top;
				void* ptr = &buffer.at(top);
				const auto result = std::align(alignof(type), sizeof(type), ptr, space);
				if (!result)
					return result;

				top = buffer.size() - space - sizeof(type);

				return new (result) type {std::forward<pack_types...>(pack...)};
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

		// Bencoding parser
		// How will memory management work for the parse nodes?
		// How often will we need to parse bencoding? It's not heavily involved in the peer protocol
		class bparser {
			using iterator = gsl::span<const char>::iterator;

		public:
			bparser() = default;
			bparser(gsl::span<const char> data) noexcept : end(data.end()), pos(data.begin()) {}

			auto try_decode() noexcept { return any(); }

		private:
			iterator end {};
			iterator pos {};

			template <typename type, type (bparser::*parse_rule)()>
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
			bool rule_symbol() noexcept
			{
				if (peek() == c) {
					++pos;
					return true;
				}

				return false;
			}

			template <char c>
			bool symbol() noexcept
			{
				return attempt<bool, &bparser::rule_symbol<c>>();
			}

			sentinel_int rule_digits() noexcept
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
						return {};
				}

				return first_digit ? sentinel_int {} : sentinel_int {gsl::narrow<std::int64_t>(value)};
			}

			auto digits() noexcept { return attempt<sentinel_int, &bparser::rule_digits>(); }

			sentinel_int rule_number() noexcept
			{
				if (!symbol<'i'>())
					return {};

				const auto leading_zero = peek() == '0';
				const auto is_negative = symbol<'-'>();
				const auto value = digits();
				if (!value)
					return {};

				if (value.value == 0 && is_negative)
					return {};

				if (value.value != 0 && leading_zero)
					return {};

				if (!symbol<'e'>())
					return {};

				return is_negative ? sentinel_int {-value.value} : value;
			}

			auto number() noexcept { return attempt<sentinel_int, &bparser::rule_number>(); }

			bool rule_list() noexcept
			{
				if (!symbol<'l'>())
					return false;

				while (true) {
					if (!any())
						break;
				}

				if (!symbol<'e'>())
					return false;

				return true;
			}

			bool list() noexcept { return attempt<bool, &bparser::rule_list>(); }

			bool rule_dictionary() noexcept
			{
				if (!symbol<'d'>())
					return false;

				// TODO: check for sorted keys
				while (true) {
					if (!string())
						break;

					if (!any())
						return false;
				}

				if (!symbol<'e'>())
					return false;

				return true;
			}

			bool dictionary() noexcept { return attempt<bool, &bparser::rule_dictionary>(); }

			bool rule_string() noexcept
			{
				const auto length = digits();
				if (!length)
					return false;

				if (!symbol<':'>())
					return false;

				if (end - pos < length.value)
					return false;

				pos += length.value;

				return true;
			}

			bool string() noexcept { return attempt<bool, &bparser::rule_string>(); }

			bool rule_any() noexcept { return number() || string() || list() || dictionary(); }

			bool any() noexcept { return attempt<bool, &bparser::rule_any>(); }
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
