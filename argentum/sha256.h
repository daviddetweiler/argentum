#pragma once

#include <array>
#include <cstdint>
#include <limits>

#include <gsl/gsl>

namespace argentum {
	constexpr auto to_uint8_tp(const void* ptr) { return static_cast<const std::uint8_t*>(ptr); }
}

namespace argentum::sha256 {
	using digest = gsl::span<std::uint8_t, 256 / 8>;

	class stomach {
		static constexpr auto sentinel = std::numeric_limits<std::size_t>::max();
		static constexpr auto block_len = 64ull;
		static constexpr auto block_mask = block_len - 1;
		static constexpr std::array<std::uint8_t, block_len> padding {0x80};

	public:
		void init() noexcept;
		void complete(digest d) noexcept;
		void append(gsl::span<const std::uint8_t> data) noexcept;

	private:
		std::array<std::uint32_t, 8> hash {};
		std::array<std::uint8_t, block_len> pending_block {};
		std::size_t position {sentinel};
	};
}
