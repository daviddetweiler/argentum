#define NOMINMAX

#include "tls_1_3.h"

#include <array>
#include <cmath>
#include <cstdint>

#include <gsl/gsl>

namespace argentum::sha256 {
	template <int n>
	constexpr std::uint32_t rotr(std::uint32_t x) noexcept
	{
		return (x >> n) | (x << (32 - n));
	}

	constexpr std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ ((~x) & z); }

	constexpr std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}

	constexpr std::uint32_t bsigma0(std::uint32_t x) { return rotr<2>(x) ^ rotr<13>(x) ^ rotr<22>(x); }
	constexpr std::uint32_t bsigma1(std::uint32_t x) { return rotr<6>(x) ^ rotr<11>(x) ^ rotr<25>(x); }
	constexpr std::uint32_t sigma0(std::uint32_t x) { return rotr<7>(x) ^ rotr<18>(x) ^ (x >> 3); }
	constexpr std::uint32_t sigma1(std::uint32_t x) { return rotr<17>(x) ^ rotr<19>(x) ^ (x >> 10); }

	template <std::size_t n, typename type>
	constexpr auto bextr(type x)
	{
		static_assert(n < sizeof(type));
		return (x >> (n * 8)) & 0xff;
	}

	constexpr auto be(std::uint64_t x)
	{
		return bextr<0>(x) << 56 | bextr<1>(x) << 48 | bextr<2>(x) << 40 | bextr<3>(x) << 32 | bextr<4>(x) << 24
			| bextr<5>(x) << 16 | bextr<6>(x) << 8 | bextr<7>(x);
	}

	constexpr auto be(std::uint32_t x)
	{
		return bextr<0>(x) << 24 | bextr<1>(x) << 16 | bextr<2>(x) << 8 | bextr<3>(x);
	}

	constexpr std::array<std::uint32_t, 64> ks_be {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	constexpr auto block_bytes = 512 / 8;
	constexpr auto padding_bytes = 448 / 8;
	using hash_state = gsl::span<std::uint32_t, 8>;
	constexpr std::array<std::uint32_t, 8> first_hash {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	};

	void hash_block(hash_state state, gsl::span<const char, block_bytes> block)
	{
		std::array<std::uint32_t, 64> w {};
		std::memcpy(w.data(), block.data(), block.size());

		for (auto t = 0; t < w.size(); ++t) {
			auto& ws = gsl::at(w, t);
			if (t < 16)
				ws = be(ws);
			else
				ws = sigma1(gsl::at(w, t - 2)) + gsl::at(w, t - 7) + sigma0(gsl::at(w, t - 15)) + gsl::at(w, t - 16);
		}

		auto a = gsl::at(state, 0);
		auto b = gsl::at(state, 1);
		auto c = gsl::at(state, 2);
		auto d = gsl::at(state, 3);
		auto e = gsl::at(state, 4);
		auto f = gsl::at(state, 5);
		auto g = gsl::at(state, 6);
		auto h = gsl::at(state, 7);

		for (auto t = 0; t < w.size(); ++t) {
			const auto bt_1 = h + bsigma1(e) + ch(e, f, g) + gsl::at(ks_be, t) + gsl::at(w, t);
			const auto bt_2 = bsigma0(a) + maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + bt_1;
			d = c;
			c = b;
			b = a;
			a = bt_1 + bt_2;
		}

		gsl::at(state, 0) += a;
		gsl::at(state, 1) += b;
		gsl::at(state, 2) += c;
		gsl::at(state, 3) += d;
		gsl::at(state, 4) += e;
		gsl::at(state, 5) += f;
		gsl::at(state, 6) += g;
		gsl::at(state, 7) += h;
	}

	void hash(digest d, gsl::span<const char> content)
	{
		auto state = first_hash;
		for (auto i = 0;; i += block_bytes) {
			const auto block_end = std::min(content.size(), gsl::narrow_cast<std::size_t>(i + block_bytes));
			const auto psize = block_end - i;
			const auto next_block = content.subspan(i, psize);
			if (block_end != content.size()) {
				hash_block(state, next_block.subspan<0, block_bytes>());
			}
			else { // Should trigger on final block
				std::array<char, block_bytes * 2> padded {};
				std::memcpy(padded.data(), next_block.data(), next_block.size());
				gsl::at(padded, psize) = gsl::narrow_cast<char>(1u << 7);
				const auto needed = (padding_bytes - ((psize + 1) % block_bytes)) % block_bytes;
				const auto padding_suffix = psize + 1 + needed;
				const auto suffix_ptr = &gsl::at(padded, padding_suffix);
				const auto length = be(gsl::narrow<std::uint64_t>(content.size() * 8));
				std::memcpy(suffix_ptr, &length, sizeof(std::uint64_t));
				const auto padded_len = padding_suffix + sizeof(std::uint64_t);
				Ensures(padded_len % block_bytes == 0);

				const gsl::span span {padded};
				hash_block(state, span.subspan<0, block_bytes>());
				if (padded_len > block_bytes)
					hash_block(state, span.subspan<block_bytes, block_bytes>());

				break;
			}
		}

		for (auto& s : state)
			s = be(s);

		std::memcpy(d.data(), state.data(), d.size());
	}
}
