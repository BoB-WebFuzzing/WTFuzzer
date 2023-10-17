--TEST--
Test with Code Coverage with path and branch checking (< PHP 7.4)
--SKIPIF--
<?php
require __DIR__ . '/../utils.inc';
check_reqs('PHP < 7.4');
?>
--INI--
xdebug.mode=coverage
xdebug.trace_options=0
xdebug.collect_return=0
xdebug.collect_assignments=0
xdebug.auto_profile=0
xdebug.dump_globals=0
xdebug.trace_format=0
--FILE--
<?php
	xdebug_start_code_coverage(XDEBUG_CC_UNUSED);
	$file = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'coverage.inc';
	include $file;
	$cc = xdebug_get_code_coverage();
	xdebug_stop_code_coverage();
	var_dump($cc[$file]);
?>
--EXPECTF--
This is a YYYY-MM-DD format.
This is a YYYYMMDD HHii format.
array(%d) {
  [2]=>
  int(1)
  [4]=>
  int(1)
  [5]=>
  int(-1)
  [7]=>
  int(1)
  [8]=>
  int(1)
  [10]=>
  int(1)
  [11]=>
  int(1)
  [14]=>
  int(-1)
  [17]=>
  int(1)
  [18]=>
  int(1)
  [20]=>
  int(1)
  [21]=>
  int(1)
  [22]=>
  int(1)
  [25]=>
  int(1)
}
