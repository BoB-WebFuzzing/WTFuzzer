--TEST--
Test for bug #842: Can't debug conditional statements without a block (TS3)
--SKIPIF--
<?php
require __DIR__ . '/../utils.inc';
check_reqs('dbgp');
?>
--FILE--
<?php
require 'dbgp/dbgpclient.php';
$filename = realpath( dirname(__FILE__) . '/bug00842.inc' );

$commands = array(
	'feature_set -n notify_ok -v 1',
	'feature_set -n resolved_breakpoints -v 1',
	"breakpoint_set -t line -f file://{$filename} -n 18",
	'run',
	'step_into',
	'step_out',
	'step_into',
	'detach',
);

dbgpRunFile( $filename, $commands );
?>
--EXPECT--
<?xml version="1.0" encoding="iso-8859-1"?>
<init xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" fileuri="file://bug00842.inc" language="PHP" xdebug:language_version="" protocol_version="1.0" appid=""><engine version=""><![CDATA[Xdebug]]></engine><author><![CDATA[Derick Rethans]]></author><url><![CDATA[https://xdebug.org]]></url><copyright><![CDATA[Copyright (c) 2002-2099 by Derick Rethans]]></copyright></init>

-> feature_set -i 1 -n notify_ok -v 1
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="feature_set" transaction_id="1" feature="notify_ok" success="1"></response>

-> feature_set -i 2 -n resolved_breakpoints -v 1
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="feature_set" transaction_id="2" feature="resolved_breakpoints" success="1"></response>

-> breakpoint_set -i 3 -t line -f file://bug00842.inc -n 18
<?xml version="1.0" encoding="iso-8859-1"?>
<notify xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" name="breakpoint_resolved"><breakpoint type="line" resolved="resolved" filename="file://bug00842.inc" lineno="18" state="enabled" hit_count="0" hit_value="0" id=""></breakpoint></notify>

<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="breakpoint_set" transaction_id="3" id="" resolved="resolved"></response>

-> run -i 4
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="run" transaction_id="4" status="break" reason="ok"><xdebug:message filename="file://bug00842.inc" lineno="18"></xdebug:message></response>

-> step_into -i 5
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="step_into" transaction_id="5" status="break" reason="ok"><xdebug:message filename="file://bug00842.inc" lineno="3"></xdebug:message></response>

-> step_out -i 6
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="step_out" transaction_id="6" status="break" reason="ok"><xdebug:message filename="file://bug00842.inc" lineno="6"></xdebug:message></response>

-> step_into -i 7
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="step_into" transaction_id="7" status="break" reason="ok"><xdebug:message filename="file://bug00842.inc" lineno="19"></xdebug:message></response>

-> detach -i 8
<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="https://xdebug.org/dbgp/xdebug" command="detach" transaction_id="8" status="stopping" reason="ok"></response>
