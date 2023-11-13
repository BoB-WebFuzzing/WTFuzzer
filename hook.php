<?php
function checkString($string, $funcname) {
    if (str_contains($string, "WTFTEST")) {
        $path = $_SERVER['PHP_SELF'];
        $fp = fopen("/home/tmp/".substr(str_replace('/', '+', $path), 1, strlen($path) - 4)."txt", 'a+');
        fwrite($fp, $funcname." : ".$string.chr(13).chr(10));
        fclose($fp);
    }
}
# MySQL
uopz_set_hook('mysqli_query', function ($mysql, $query) {
    checkString($query, "mysqli_query");
});

uopz_set_hook('mysqli_multi_query', function ($mysql, $query) {
    checkString($query, "mysqli_multi_query");
});

# SQLite
uopz_set_hook('SQLite3', 'query', function ($query) {
    checkString($query, "SQLite3::query");
});

uopz_set_hook('SQLite3', 'exec', function ($query) {
    checkString($query, "SQLite3::exec");
});

# PDO
uopz_set_hook('PDO', 'prepare', function ($query) {
    checkString($query, "PDO::prepare");
});

uopz_set_hook('PDO', 'query', function ($query) {
    checkString($query, "PDO::query");
});

# PostgreSQL
uopz_set_hook('pg_execute', function ($connection, $stmtname, $params) {
    for ($i = 0; $i < count($params); $i++) {
        checkString($params[$i], "pg_execute");
    }
});

uopz_set_hook('pg_query', function ($connection, $query) {
    checkString($query, "pg_query");
});

uopz_set_hook('pg_query_params', function ($connection, $query, $params) {
    for ($i = 0; $i < count($params); $i++) {
        checkString($params[$i], "pg_query_params");
    }
});

# MongoDB
uopz_set_hook('find', function ($filter, $options) {});

uopz_set_hook('findOne', function () {});

uopz_set_hook('findAndModify', function () {});

uopz_set_hook('drop', function () {});

uopz_set_hook('insert', function () {});

uopz_set_hook('update', function () {});

# SSRF
uopz_set_hook('file_get_contents', function ($filename) {
    checkString($filename, "file_get_contents");
});

uopz_set_hook('curl_exec', function () {});

uopz_set_hook('fopen', function ($filename, $mode) {
    checkString($filename, "fopen");
});

uopz_set_hook('file', function ($filename) {
    checkString($filename, "file");
});

# File Upload
uopz_set_hook('move_uploaded_file', function ($from, $to) {
    checkString($from, "move_uploaded_file");
    checkString($to, "move_uploaded_file");
});

uopz_set_hook('copy', function ($from, $to) {
    checkString($from, "copy");
    checkString($to, "copy");
});

# File Download
uopz_set_hook('readfile', function ($filename) {
    checkString($filename, "readfile");
});

# File Deletion
uopz_set_hook('unlink', function ($filename) {
    checkString($filename, "unlink");
});

/*
xdebug_start_trace("/home/tmp/xdebug.trace", XDEBUG_TRACE_APPEND);

class coverage_dumper
{
    function __destruct()
    {
        try {
            $traceFile = xdebug_stop_trace();

            echo "Trace file saved to: $traceFile" . PHP_EOL;
        } catch (Exception $ex) {
            echo str($ex);
        }
    }
}
*/
?>


