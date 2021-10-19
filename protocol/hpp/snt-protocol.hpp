#pragma once
#include "../snt-protocol.h"

namespace libsnt {

	class SntBlock {
	  public:
		template <typename T>
		void addNextSection(SntPackageSection nextSection, T &section, unsigned int length = sizeof(T)) {
			//Set current section map to the next section.

		}


	};
} // namespace libsnt