--TEST--
Test for variable member functions
--INI--
xdebug.mode=trace
xdebug.start_with_request=no
xdebug.collect_return=0
xdebug.collect_assignments=0
xdebug.trace_format=0
--FILE--
<?php
require_once 'capture-trace.inc';

class a {

	function func_a1() {
	}

	function func_a2() {
	}

}

$A = new a;
$A->func_a1();

$a = 'func_a2';
$A->$a();

xdebug_stop_trace();
?>
--EXPECTF--
TRACE START [%d-%d-%d %d:%d:%d.%d]
%w%f %w%d     -> a->func_a1() %stest15.php:15
%w%f %w%d     -> a->func_a2() %stest15.php:18
%w%f %w%d     -> xdebug_stop_trace() %stest15.php:20
%w%f %w%d
TRACE END   [%d-%d-%d %d:%d:%d.%d]
