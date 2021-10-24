#include "snt_bitencoding.h"
#include <gtest/gtest.h>

class BitEncodingManchesterTest
	: public ::testing::TestWithParam<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>> {};

TEST_P(BitEncodingManchesterTest, Values) {
	auto [x, expected] = GetParam();
	std::vector<uint8_t> enc(x.size());
	std::vector<uint8_t> dec(x.size());
	snt_bit_encoding(SntBitEncoding_Manchester, (const uint32_t *)x.data(), (uint32_t *)enc.data(), x.size());
	snt_bit_decoding(SntBitEncoding_Manchester, (const uint32_t *)enc.data(), (uint32_t *)dec.data(), dec.size());
	/*	Compare - */
	ASSERT_EQ(dec, expected);
}

INSTANTIATE_TEST_SUITE_P(
	BitEncodingTest, BitEncodingManchesterTest,
	::testing::Values(std::make_tuple(std::vector<uint8_t>{1, 2, 3, 4, 5}, std::vector<uint8_t>{1, 2, 3, 4, 5}),
					  std::make_tuple(std::vector<uint8_t>{5, 5, 5, 5, 5}, std::vector<uint8_t>{5, 5, 5, 5, 5})));