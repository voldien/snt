/**
    Simple network benchmark tool.
    Copyright (C) 2017  Valdemar Lindberg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#ifndef _SNT_DEFS_H_
#define _SNT_DEFS_H_ 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 *	Version marcros.
 *	[ major 6 bits | minor 10 bits ]
 */
#define SNT_VERSION ((SNT_MAJOR << 10) | (SNT_MINOR & 0x3FF))       /*	SNT version.	*/
#define SNT_GET_MAJ_VERSION(ver) ((ver & ~0x3FF) >> 10)             /*	Extract major version.	*/
#define SNT_GET_MIN_VERSION(ver) (ver & 0x3FF)                      /*	Extract minor version.	*/

/**
 *    Compiler.
 */
#ifdef _MSC_VER 	/*	Visual Studio C++ Compiler.	*/
	#define SNT_VC
	#define SNT_COMPILER 1
	#if _MSC_VER >= 1900
		#define SNT_V13 _MSC_VER
	#elif _MSC_VER >= 1800
		#define SNT_V12 _MSC_VER
	#elif _MSC_VER >= 1700
		#define SNT_VC11 _MSC_VER
	#elif _MSC_VER >= 1600
		#define SNT_VC10 _MSC_VER
	#elif _MSC_VER >= 1500
		#define SNT_VC9 _MSC_VER
	#elif _MSC_VER >= 1400
		#define SNT_VC8 _MSC_VER
	#elif _MSC_VER >= 1300
		#define SNT_VC7 _MSC_VER
	#else
		#define SNT_VC6 _MSC_VER
	#endif
    	#pragma warning(disable : 4201)
	#define SNT_COMPILER_NAME "Visual Studio C++/C"

#elif defined(__clang__)  || defined(__llvm__)           /*  LLVM, clang   */
    #define SNT_LLVM 1
	#define SNT_CLANG 1
	#define SNT_COMPILER 5
	#define SNT_COMPILER_NAME "LLVM/CLANG"
	#define SNT_COMPILER_MAJOR_VERSION __clang_major__
	#define SNT_COMPILER_MINOR_VERSION __clang_minor__

#elif defined(__GNUC__) || defined(__SNC__) || defined( __GNUC_MINOR__)	/*  GNU C Compiler*/
	#define SNT_GNUC 1
	#define SNT_COMPILER 2
	#define SNT_COMPILER_NAME "GNU C"
	#define SNT_COMPILER_MAJOR_VERSION __clang_major__
	#define SNT_COMPILER_MINOR_VERSION __clang_minor__

#elif defined(__GNUG__) /*  GNU C++ Compiler*/
	#define SNT_GNUC 2

#elif defined(__ghs__)		/* GHS	*/
	#define SNT_GHS 1
	#define SNT_COMPILER 3

#elif defined(__HP_cc) || defined(__HP_aCC)			/*	*/

#elif defined(__PGI)			/*	*/

#elif defined(__ICC) || defined(__INTEL_COMPILER) /*  Intel Compiler  */
	#define SNT_INTEL
	#define SNT_COMPILER 4
	#define SNT_COMPILER_NAME "Intel C++"

#elif defined(__SUNPRO_C) || defined(__SUNPRO_CC)

#else
	#error Unsupported Compiler.
#endif


/**
 *	Platform define
 *	Architecture!
 */
#ifdef SNT_VC
	#if defined(_M_IX86) || defined(_WIN32)
		#define SNT_X86                          /**/
		#define SNT_X32                          /**/
		#define SNT_WIN32                        /**/
		#define SNT_WINDOWS                      /**/
		#define SNT_ARCH "x86"
	#elif defined(_M_X64) || defined(_WIN64)
		#define SNT_X64                          /**/
		#define SNT_WIN64                        /**/
		#define SNT_WINDOWS                      /**/
		#define SNT_ARCH "x64"
	#elif defined(_M_PPC)
		#define SNT_PPC                          /**/
		#define SNT_X360                         /**/
		#define SNT_VMX                          /**/
	#elif defined(_M_ARM)
		#define SNT_ARM                          /**/
		#define SNT_ARCH "arm"
		#define SNT_ARM_NEON                     /**/
	#endif
#elif defined(SNT_GNUC) || defined(SNT_CLANG)
	#ifdef __CELLOS_LV2__   /**/
        #define SNT_PS3                          /*	playstation 3*/
	#elif defined(__arm__)	/**/
		#define SNT_ARM
        #define SNT_PSP2                         /*	playstation portable 2*/
        #define SNT_RAS_PI                       /*	rasberry pi	*/
	#endif
	#if defined(_WIN32) /**  Window*/
		#define SNT_X86
		#define SNT_WINDOWS                      /**/
	#endif
	#if ( defined(__linux__) || defined(__linux) || defined(linux) ) && (!(__ANDROID__) || !(ANDROID))	/* Linux */
		#define SNT_LINUX 1                       /**/
		#if defined(__amd64) || defined(__x86_64__) || defined(__i386__)
            #define SNT_X86 1
			#define SNT_ARCH "amd64"
		#endif
		#if defined(__arm__)
              #define EX_ARM 1
        #endif

	#elif defined (ANDROID) || defined(__ANDROID__) || __ANDROID_API__ > 9  /** Android */
        #include<jni.h>
		#define SNT_ANDROID 1
		/*  android Architecture*/
        #if defined(__arm__)
			#define SNT_ARM 1
		  #if defined(__ARM_ARCH_7A__)
			#if defined(__ARM_NEON__)
			  #if defined(__ARM_PCS_VFP)
				#define SNT_ABI "armeabi-v7a/NEON (hard-float)"
			  #else
				#define SNT_ABI "armeabi-v7a/NEON"
			  #endif
			#else
			  #if defined(__ARM_PCS_VFP)
				#define SNT_ABI "armeabi-v7a (hard-float)"
			  #else
				#define SNT_ABI "armeabi-v7a"
			  #endif
			#endif
		  #else
		   #define SNT_ABI "armeabi"
		  #endif
		#elif defined(__i386__)
		   #define SNT_ABI "x86"
		#elif defined(__x86_64__)
		   #define SNT_ABI "x86_64"
		#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
		   #define SNT_ABI "mips64"
		#elif defined(__mips__)
		   #define SNT_ABI "mips"
		#elif defined(__aarch64__)
		   #define SNT_ABI "arm64-v8a"
		#else
		   #define SNT_ABI "unknown"
		#endif

	#elif defined (__APPLE__)   /*  Apple product   */
		#define SNT_APPLE 1
		#if defined(__arm__)
			#define SNT_APPLE_IOS    /*  Apple iphone/ipad OS    */
		#elif defined(MACOSX) || defined(macintosh) || defined(Macintosh)
			#define EX_MAC 1
		#endif
	#elif defined(__CYGWIN) 	/**/
		#define SNT_CYGWIN 1
		#define SNT_LINUX 1
	#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)   /*  BSD*/
		#define SNT_BSD
    	#elif defined(__llvm__) || defined(__clang__)   	/*  llvm    */
        	#define SNT_LLVM 1
	#endif

#elif defined(__ICC) || defined(__INTEL_COMPILER)


#else
	#error  Unsupported architecture!   /*  No architecture support implicitly. remove this line to compile anyway*/
#endif

/**
 *	Check if UNIX platform.
 */
#if defined(__unix__) || defined(__unix) || defined(unix)	/*  Unix    */
	#   define SNT_UNIX 1
#endif


/**
 *	Calling function convention.
 */
#ifdef SNT_WINDOWS	        /** Windows Calling Convention.*/
	#define SNTAPIENTRY     __cdecl
	#define SNTAPIFASTENTRY __fastcall
	#define SNTAPITHISENTRY __thiscall
	#define SNTAPISTDENTRY  __stdcall
#elif defined(SNT_ANDROID)   /** Android Calling Convention	*/
    #define SNTAPIENTRY JNICALL
    #define SNTAPIFASTENTRY JNICALL
    #define SNTAPITHISENTRY JNICALL
    #define SNTAPISTDENTRY JNICALL
#else
#   if !defined(__cdecl) && ( defined(SNT_GNUC)  || defined(SNT_CLANG) )
        #define __cdecl  __attribute__ ((__cdecl__))
        #define __stdcall  __attribute__ ((stdcall))
		#define __fastcall __attribute__((fastcall))
#   endif
	#define SNTAPIENTRY     __cdecl
	#define SNTAPISTDENTRY  __stdcall
	#define SNTAPIFASTENTRY __fastcall
#endif


/**
 *	Restrict declaration.
 */
#ifndef SNT_RESTRICT
	#if defined(SNT_GNUC)
		#define SNT_RESTRICT __restrict
	#elif defined(SNT_CLANG)
	    #define SNT_RESTRICT __restrict
	#elif defined(SNT_VC)
		#define SNT_RESTRICT __declspec(restrict)
    #else
	    #define SNT_RESTRICT
	#endif
#endif




#endif
