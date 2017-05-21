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
#ifndef _SNT_TIME_H_
#define _SNT_TIME_H_ 1

/**
 *	Get time in nano seconds.
 */
extern long int sntGetNanoTime(void);

/**
 *	Get time since Epoch.
 */
extern long int sntGetUnixTime(void);

/**
 *	Get time resolution.
 */
extern long int sntGetTimeResolution(void);

/**
 *	Sleep current thread in n number of
 *	nano seconds.
 */
extern void sntNanoSleep(long int nanosec);

#endif
