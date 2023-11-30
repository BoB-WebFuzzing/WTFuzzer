--TEST--
Bug #75420.9 (Indirect modification of magic method argument)
--FILE--
<?php
class Test implements ArrayAccess {
    public function offsetExists($x): bool { $GLOBALS["name"] = 24; return true; }
    public function offsetGet($x): mixed { var_dump($x); return 42; }
    public function offsetSet($x, $y): void { }
    public function offsetUnset($x): void { }
}

$obj = new Test;
$name = "foo";
var_dump($obj[$name] ?? 12);
var_dump($name);
?>
--EXPECT--
string(3) "foo"
int(42)
int(24)
