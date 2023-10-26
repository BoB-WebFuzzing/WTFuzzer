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

#ifndef __XDEBUG_GC_STATS_H__
#define __XDEBUG_GC_STATS_H__

typedef struct _xdebug_gc_stats_settings_t {
	char      *output_name;
} xdebug_gc_stats_settings_t;

typedef struct _xdebug_gc_stats_globals_t {
	/* garbage stats */
	zend_bool  active;
	FILE      *file;
	char      *filename;
} xdebug_gc_stats_globals_t;

void xdebug_gcstats_init_if_requested(zend_op_array* op_array);

void xdebug_init_gc_stats_globals(xdebug_gc_stats_globals_t *xg);
void xdebug_gcstats_minit();
void xdebug_gcstats_mshutdown();
void xdebug_gcstats_rinit();
void xdebug_gcstats_rshutdown();

#endif
