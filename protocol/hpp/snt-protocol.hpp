#pragma once
#include "../snt-protocol.h"

namespace LIBSNT {

	class SntBlock {

		template <typename T>
		void addNextSection(SntPackageSection nextSection, T &section, unsigned int length = sizeof(T)) {}
	};
} // namespace LIBSNT