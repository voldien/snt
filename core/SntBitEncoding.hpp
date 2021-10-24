#ifndef _SNT_BIT_ENCONDING_HPP_
#define _SNT_BIT_ENCONDING_HPP_ 1

namespace libsnt {
	class SntBitEncoding {
	  public:
		SntBitEncoding(enum SntBitEncoding encoding);

		template <typename T> void encoding(const T &src, T &dst, unsigned int size = sizeof(T)) {}
		template <typename T> void decoding(const T &src, T &dst, unsigned int size = sizeof(T)) {}
	};

} // namespace libsnt

#endif
