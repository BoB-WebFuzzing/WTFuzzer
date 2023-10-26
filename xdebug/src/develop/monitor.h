/*
   +----------------------------------------------------------------------+
   | Xdebug                                                               |
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2020 Derick Rethans                               |
   +----------------------------------------------------------------------+
   | This source file is subject to version 1.01 of the Xdebug license,   |
   | that is bundled with this package in the file LICENSE, and is        |
   | available at through the world-wide-web at                           |
   | https://xdebug.org/license.php                                       |
   | If you did not receive a copy of the Xdebug license and are unable   |
   | to obtain it through the world-wide-web, please send a note to       |
   | derick@xdebug.org so we can mail you a copy immediately.             |
   +----------------------------------------------------------------------+
 */

#ifndef __HAVE_XDEBUG_MONITOR_H__
#define __HAVE_XDEBUG_MONITOR_H__

typedef struct xdebug_monitored_function_entry
{
	char        *func_name;
	zend_string *filename;
	int          lineno;
} xdebug_monitored_function_entry;

void xdebug_monitored_function_dtor(void *dummy, void *elem);

#endif
