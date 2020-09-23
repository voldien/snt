CMAKE_MINIMUM_REQUIRED( VERSION 3.0 )
PROJECT(fragview VERSION 0.13.1 LANGUAGES C)

# Build shared/dynamic library option
OPTION(BUILD_SHARED_LIBS "Build package with shared libraries." ON)
OPTION(BUILD_WITH_COVERAGE "Enable profiling and coverage report analysis." OFF)
OPTION(BUILD_WITH_PROFILER "Enable profiling." OFF)
OPTION(BUILD_WITH_INSTALL "Disable this if you want to use as a submodule." ON )
OPTION(BUILD_WITH_UBSAN "" OFF)
OPTION(BUILD_WITH_ASAN "Enable AddressSanitizer." OFF )
OPTION(BUILD_OPT_BUILD_PACKAGES "Set to ON to generate CPack configuration files and packaging targets" OFF)
OPTION(BUILD_WITH_DEBUG_BOUNDSCHECK "Array/Pointer BoundsChecking, buffer overflow protection. Used in debug only." OFF)
OPTION(BUILD_WITH_TEST "Enable Testing." OFF)

IF(MSVC)
  OPTION( BUILD_INSTALL_PDB
	"Install MSVC debug files."
	ON
  )
  IF(NOT (MSVC_VERSION LESS 1900))
	# Multibyte character set is deprecated since at least MSVC2015 (possibly earlier)
	ADD_DEFINITIONS( -DUNICODE -D_UNICODE )
  ENDIF()
ENDIF()


# Set version of the project.
SET(VERSION_MAJOR 0)
SET(VERSION_MINOR 13)
SET(VERSION_REVISION 1)
SET(VERSION_STATE b)
SET(VERSION ${VERSION_MAJOR}.${VERSION_MINOR}${VERSION_STATE}${VERSION_REVISION} )
SET(PROJECT_VERSION "${VERSION}")


# GCC compiler flag options.
IF((CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX) AND NOT CMAKE_COMPILER_IS_MINGW)
	IF (BUILD_SHARED_LIBS AND CMAKE_SIZEOF_VOID_P EQUAL 8) # -fPIC is only required
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
	ENDIF() 

	ADD_DEFINITIONS(-DSNT_MAJOR=${VERSION_MAJOR} -DSNT_MINOR=${VERSION_MINOR})
	ADD_DEFINITIONS(-DSNT_STR_VERSION="${VERSION}")
	ADD_DEFINITIONS(-Werror)

	IF (CMAKE_BUILD_TYPE STREQUAL "Release")
		MESSAGE(STATUS "Compile for release.")
		ADD_DEFINITIONS(-DNDEBUG=1)
		ADD_DEFINITIONS(-O3)
		SET(CMAKE_RELEASE TRUE)
	ELSE()
		MESSAGE(STATUS "Compile for debug.")
		ADD_DEFINITIONS(-D_DEBUG)
		ADD_DEFINITIONS(-g3 -O0)
		SET(CMAKE_DEBUG TRUE)
	ENDIF()

	#
	IF(BUILD_WITH_COVERAGE)
		MESSAGE(STATUS "Building with coverage")
		SET(GCC_COVERAGE_COMPILE_FLAGS "--coverage -fprofile-arcs -ftest-coverage")
		SET(GCC_COVERAGE_LINK_FLAGS    "-lgcov")
		SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
		SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
		SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
	ENDIF()

	#
	IF(BUILD_WITH_PROFILER)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
		SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
		SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
	ENDIF()

	#
	IF (BUILD_WITH_UBSAN)
		MESSAGE(STATUS "Undefined Behavior sanitizer enabled")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined,shift,shift-exponent,integer-divide-by-zero,unreachable,vla-bound,null,return,signed-integer-overflow,bounds,float-divide-by-zero,float-cast-overflow,nonnull-attribute,returns-nonnull-attribute,bool,enum,vptr,pointer-overflow,builtin -fno-sanitize-recover=all")
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined,shift,shift-exponent,integer-divide-by-zero,unreachable,vla-bound,null,return,signed-integer-overflow,bounds,float-divide-by-zero,float-cast-overflow,nonnull-attribute,returns-nonnull-attribute,bool,enum,vptr,pointer-overflow,builtin -fno-sanitize-recover=all")
	ENDIF()
	#
	IF (BUILD_WITH_ASAN)
		MESSAGE(STATUS "AddressSanitizer enabled")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
	ENDIF()
ELSEIF ( "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang" )
  SET(CMAKE_CXX_FLAGS "-fvisibility=hidden -fno-strict-aliasing -Wall -Wno-long-long ${CMAKE_CXX_FLAGS}" )
  SET(CMAKE_C_FLAGS "-fno-strict-aliasing ${CMAKE_C_FLAGS}")
ELSEIF(MSVC)
	# Enable multi-core compilation with MSVC
	IF( "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang" ) # clang-cl
		ADD_COMPILE_OPTIONS(/bigobj /W4 /WX )
	ELSE() # msvc
		ADD_COMPILE_OPTIONS(/MP /bigobj /W4 /WX)
	ENDIF()

	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /D_DEBUG /Zi /Od")
ELSEIF ( "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang" )
	SET(CMAKE_CXX_FLAGS "-g -fvisibility=hidden -fno-strict-aliasing -Wall -Wno-long-long ${CMAKE_CXX_FLAGS}" )
	SET(CMAKE_C_FLAGS "-fno-strict-aliasing ${CMAKE_C_FLAGS}")
ELSEIF( CMAKE_COMPILER_IS_MINGW )
	SET(CMAKE_CXX_FLAGS "-fvisibility=hidden -fno-strict-aliasing -Wall -Wno-long-long -Wa,-mbig-obj ${CMAKE_CXX_FLAGS}")
	SET(CMAKE_C_FLAGS "-fno-strict-aliasing ${CMAKE_C_FLAGS}")
	ADD_DEFINITIONS( -U__STRICT_ANSI__ )
ELSE()

ENDIF()

# Define all file lists.
FILE(GLOB SOURCE_FILES  ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
FILE(GLOB HEADER_FILES  ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)

SET(SNT_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")

FIND_PACKAGE(ZLIB)
FIND_PACKAGE(Backtrace)
FIND_PACKAGE(OpenSSL)

# Core library for adding support for plugin.
ADD_EXECUTABLE(snt ${SOURCE_FILES} ${HEADER_FILES} )
TARGET_LINK_LIBRARIES(snt m ${OPENSSL_CRYPTO_LIBRARY} lz4 pthread z ssl bz2)

#
SET_TARGET_PROPERTIES(snt PROPERTIES
		COMPILE_FLAGS "${ZIP_CFLAGS_OTHER}")
TARGET_INCLUDE_DIRECTORIES(snt PRIVATE PUBLIC ${SNT_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES (snt PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
	$<INSTALL_INTERFACE:include>)


#make cert
#make install_cert
#install_wireshark