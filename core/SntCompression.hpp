#pragma once
#include "snt_compression.h"
#include <istream>
#include <ostream>

namespace libsnt {

	class SNTDECLSPEC Compression {
	  public:
		Compression() = delete;
		Compression(SntCompressionAlgorithm algorithm) { sntCreateCompressionContext(&context, algorithm); }
		virtual ~Compression() { sntDeleteCompressionContext(context); }

		SntCompressionAlgorithm getCompression() {}

		template <typename T> long int inflate(const T &, unsigned int length) {}
		template <typename T> long int deflate(const T &, unsigned int length) {}

		Compression &operator>>(bool &data) {}

	  private:
		SntCompressionContext *context;
	};
} // namespace libsnt