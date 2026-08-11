#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include <gsl/gsl>

namespace argentum::rijndael {
	namespace {
		using t_table = std::array<std::uint32_t, 256>;
		using u_op = std::array<std::uint8_t, 256>;
		using b_op = std::array<u_op, 256>;
		static_assert(sizeof(b_op) == sizeof(u_op) * 256);

		struct t_tables {
			t_table t0;
			t_table t1;
			t_table t2;
			t_table t3;
		};

		constexpr auto pack(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d)
		{
			return gsl::narrow_cast<std::uint32_t>(a | b << 8 | c << 16 | d << 24);
		};

		template <unsigned int i>
		static constexpr std::uint8_t rotate(std::uint8_t b)
		{
			return (b << i) | (b >> (7 & (0u - i)));
		}

		static constexpr std::uint8_t times_x(std::uint8_t n)
		{
			const auto t = gsl::narrow_cast<std::uint8_t>(n << 1);
			return (n & 0x80) ? t ^ 0x1b : t;
		}

		static constexpr std::uint8_t multiply(std::uint8_t a, std::uint8_t b)
		{
			std::uint8_t c {};
			for (; a; a >>= 1, b = times_x(b))
				c ^= (a & 0x01) ? b : 0x0u;

			return c;
		}

		struct constant_table {
			std::array<std::uint8_t, (14 + 1) * 8 / 4> round_constants;
			u_op sbox;
			u_op inverse_sbox;
			t_tables round;
			t_tables inverse_round;

			[[gsl::suppress(bounds)]] //
			[[gsl::suppress(f.6)]] //
			inline constant_table() :
				round_constants {},
				sbox {},
				inverse_sbox {},
				round {},
				inverse_round {}
			{
				auto times_table = std::make_unique<b_op>();
				auto inverse_table = std::make_unique<u_op>();
				auto& times = *times_table;
				auto& inverse = *inverse_table;
				for (auto i = 0u; i < 256u; ++i) {
					for (auto j = i; j < 256u; ++j) {
						const auto a = gsl::narrow_cast<std::uint8_t>(i);
						const auto b = gsl::narrow_cast<std::uint8_t>(j);
						const auto c = multiply(a, b);
						times[a][b] = times[b][a] = c;
						if (c == 0x01u) {
							inverse[a] = b;
							inverse[b] = a;
						}
					}
				}

				round_constants[1] = 0x01;
				for (auto i = 2u; i < round_constants.size(); ++i)
					round_constants[i] = times[round_constants[i - 1]][0x02];

				for (auto i = 0u; i < 256u; ++i) {
					const auto b = gsl::narrow_cast<std::uint8_t>(i);
					const auto ib = inverse[b];
					const auto sb = gsl::narrow_cast<std::uint8_t>(
						rotate<4>(ib) ^ rotate<3>(ib) ^ rotate<2>(ib) ^ rotate<1>(ib) ^ ib ^ 0x63u);

					sbox[b] = sb;
					inverse_sbox[sb] = b;

					const auto sb2 = times[sb][0x02];
					const auto sb3 = times[sb][0x03];
					round.t0[b] = pack(sb2, sb, sb, sb3);
					round.t1[b] = pack(sb3, sb2, sb, sb);
					round.t2[b] = pack(sb, sb3, sb2, sb);
					round.t3[b] = pack(sb, sb, sb3, sb2);

					const auto b9 = times[b][0x09];
					const auto bb = times[b][0x0b];
					const auto bd = times[b][0x0d];
					const auto be = times[b][0x0e];
					inverse_round.t0[sb] = pack(be, b9, bd, bb);
					inverse_round.t1[sb] = pack(bb, be, b9, bd);
					inverse_round.t2[sb] = pack(bd, bb, be, b9);
					inverse_round.t3[sb] = pack(b9, bd, bb, be);
				}

				times_table.reset();
				inverse_table.reset();
			}
		};

		static constexpr std::array shifts {
			std::array {0ull, 1ull, 2ull, 3ull},
			std::array {0ull, 1ull, 2ull, 3ull},
			std::array {0ull, 1ull, 2ull, 3ull},
			std::array {0ull, 1ull, 2ull, 4ull},
			std::array {0ull, 1ull, 3ull, 4ull},
		};

		template <unsigned int nk, unsigned int nb>
		class [[gsl::suppress(bounds)]] transcoder {
			static_assert(nk >= 4 && nb >= 4 && nk <= 8 && nb <= 8, "not a valid Rijndael cipher");

		public:
			constexpr static auto key_size = nk * 4;
			constexpr static auto block_size = nb * 4;
			constexpr static auto n_rounds = std::max(10u + nk - 4u, 10u + nb - 4u);
			constexpr static auto n_key_words = (n_rounds + 1) * nb;
			using key_view = std::span<const std::uint8_t, key_size>;
			using block_view = std::span<std::uint8_t, block_size>;

			[[gsl::suppress(gsl.view)]] inline transcoder(const constant_table& c, key_view k) noexcept : transcoder {}
			{
				apply_key(c, k);
			}

			[[gsl::suppress(gsl.view)]] inline void apply_key(const constant_table& table, key_view k) noexcept
			{
				std::memcpy(keys.data(), k.data(), k.size_bytes());
				apply_key_schedule(table);
				std::memcpy(inverse_keys.data(), keys.data(), keys.size());
				const std::span view {inverse_keys};
				for (auto r = 1ull; r < n_rounds; ++r) {
					for (auto c = 0ull; c < nb; ++c)
						inverse_mix_column(table, column {view.subspan(((r * nb) + c) * 4, 4)});
				}
			}

			void inline encrypt(const constant_table& table, block_view p) const noexcept
			{
				apply_rounds<false>(table, p);
			}

			void inline decrypt(const constant_table& table, block_view c) const noexcept
			{
				apply_rounds<true>(table, c);
			}

		private:
			using round_key_view = std::span<const std::uint8_t, block_size>;
			using round_keys = std::array<std::uint8_t, n_key_words * 4>;
			using column = std::span<std::uint8_t, 4>;

			round_keys keys {};
			round_keys inverse_keys {};

			transcoder() = default;

			[[gsl::suppress(bounds)]] [[gsl::suppress(
				gsl.view)]] static void inline inverse_mix_column(const constant_table& table, column c) noexcept
			{
				const auto& [t0, t1, t2, t3] = table.inverse_round;
				const auto& sbox = table.sbox;
				const auto x = t0[sbox[c[0]]];
				const auto y = t1[sbox[c[1]]];
				const auto z = t2[sbox[c[2]]];
				const auto w = t3[sbox[c[3]]];
				const auto nc = x ^ y ^ z ^ w;
				std::memcpy(c.data(), &nc, 4);
			}

			static constexpr auto rotate_word(std::uint32_t c) { return c >> 8 | c << 24; }

			[[gsl::suppress(bounds)]] //
			static constexpr auto sub_word(const constant_table& table, std::uint32_t c)
			{
				const auto& sbox = table.sbox;
				const auto x = sbox[c & 0xff];
				const auto y = sbox[(c >> 8) & 0xff];
				const auto z = sbox[(c >> 16) & 0xff];
				const auto w = sbox[(c >> 24) & 0xff];
				return pack(x, y, z, w);
			}

			[[gsl::suppress(bounds)]] //
			[[gsl::suppress(gsl.view)]] //
			inline void apply_key_schedule(const constant_table& table) noexcept
			{
				const std::span key_view {keys};
				for (auto j = nk; j < n_key_words; ++j) {
					const column a {key_view.subspan((j - 1) * 4ull, 4)};
					const column b {key_view.subspan((j - nk) * 4ull, 4)};
					const column c {key_view.subspan(j * 4ull, 4)};

					std::uint32_t x, y;
					std::memcpy(&x, a.data(), a.size());
					std::memcpy(&y, b.data(), b.size());
					if (j % nk == 0) {
						x = sub_word(table, rotate_word(x)) ^ table.round_constants[j / nk];
					}
					else if constexpr (nk > 6) {
						if (j % nk == 4)
							x = sub_word(table, x);
					}

					x ^= y;
					std::memcpy(c.data(), &x, c.size());
				}
			}

			template <bool inverted>
			[[gsl::suppress(bounds)]] //
			[[gsl::suppress(gsl.view)]] //
			void apply_rounds(const constant_table& table, block_view state) const noexcept
			{
				const std::span key_view {inverted ? inverse_keys : keys};
				const auto offset = [](unsigned int r) { return (inverted ? n_rounds - r : r) * block_size; };
				const auto round_key = [&offset, key_view](unsigned int r) {
					return round_key_view {key_view.subspan(offset(r), block_size)};
				};

				const auto first_key = round_key(0);
				for (auto i = 0ull; i < nb; ++i) {
					std::uint32_t a, b;
					std::memcpy(&a, &state[i * 4], 4);
					std::memcpy(&b, &first_key[i * 4], 4);
					a ^= b;
					std::memcpy(&state[i * 4], &a, 4);
				}

				std::array<std::uint8_t, block_size> other {};
				for (auto i = 1u; i < n_rounds; ++i) {
					const auto a = (i % 2) ? state : other;
					const auto b = (i % 2) ? other : state;
					apply_round<inverted, false>(table, a, round_key(i), b);
				}

				const auto a = (n_rounds % 2) ? state : other;
				const auto b = (n_rounds % 2) ? other : state;
				apply_round<inverted, true>(table, a, round_key(n_rounds), b);

				if constexpr (n_rounds % 2)
					std::memcpy(state.data(), other.data(), block_size);
			}

			template <bool inverted>
			[[gsl::suppress(bounds)]] [[gsl::suppress(gsl.view)]] static constexpr auto
			get_byte(block_view state, std::uint64_t r, std::uint64_t c)
			{
				static constexpr std::span row_shifts = shifts[nb - 4];
				const auto shift = row_shifts[r];
				const auto new_c = (inverted ? c + (nb - shift) : c + shift) % nb;
				return state[new_c * 4 + r];
			};

			template <bool inverted, bool skip_mix>
			[[gsl::suppress(bounds)]] [[gsl::suppress(gsl.view)]] static void apply_round(
				const constant_table& table,
				block_view state,
				round_key_view round_key,
				block_view nstate) noexcept
			{
				const auto& sbox = inverted ? table.inverse_sbox : table.sbox;
				static constexpr auto get = [](auto&&... args) { return get_byte<inverted>(args...); };
				for (auto j = 0ull; j < nb; ++j) {
					std::uint32_t k;
					std::memcpy(&k, &round_key[j * 4], 4);
					if constexpr (!skip_mix) {
						auto& [t0, t1, t2, t3] = inverted ? table.inverse_round : table.round;
						const auto x = t0[get(state, 0, j)];
						const auto y = t1[get(state, 1, j)];
						const auto z = t2[get(state, 2, j)];
						const auto w = t3[get(state, 3, j)];
						const auto n = x ^ y ^ z ^ w ^ k;
						std::memcpy(&nstate[j * 4], &n, 4);
					}
					else {
						const auto s = pack(
							sbox[get(state, 0, j)],
							sbox[get(state, 1, j)],
							sbox[get(state, 2, j)],
							sbox[get(state, 3, j)]);

						const auto n = s ^ k;
						std::memcpy(&nstate[j * 4], &n, 4);
					}
				}
			}
		};

		using aes128 = transcoder<4, 4>;
		using aes192 = transcoder<6, 4>;
		using aes256 = transcoder<8, 4>;
	}
}
