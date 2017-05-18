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
#ifndef _SNT_DEF_H_
#define _SNT_DEF_H_
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

/**
 *
 */
#define SNT_VERSION ((SNT_MAJOR << 10) | (SNT_MINOR & 0x3FF))		/*	SNT version.	*/
#define SNT_GET_MAJ_VERSION(ver) ((ver & ~0x3FF) >> 10)				/*	Extract major version.	*/
#define SNT_GET_MIN_VERSION(ver) (SNT_MINOR & 0x3FF)				/*	Extract minor version.	*/

#endif
