<?php
function checkString($string) {
    if (str_contains($string, "WTFTEST")) {
        $path = $_SERVER['PHP_SELF'];
        $fp = fopen("/home/tmp/".substr(str_replace('/', '+', $path), 1, strlen($path) - 4)."txt", 'a+');
        fwrite($fp, $string.chr(13).chr(10));
        fclose($fp);
    }
}
# MySQL
uopz_set_hook('mysqli_query', function ($mysql, $query) {
    checkString($query);
});

uopz_set_hook('mysqli_multi_query', function ($mysql, $query) {
    checkString($query);
});

# SQLite
uopz_set_hook('SQLite3', 'query', function ($query) {
    checkString($query);
});

uopz_set_hook('SQLite3', 'exec', function ($query) {
    checkString($query);
});

# PDO
uopz_set_hook('PDO', 'prepare', function ($query) {
    echo "\n------\n", $query, "\n------\n";
});

uopz_set_hook('PDO', 'query', function ($query) {
    checkString($query);
});

# PostgreSQL
uopz_set_hook('pg_execute', function ($connection, $stmtname, $params) {
    for ($i = 0; $i < count($params); $i++) {
        checkString($params[$i]);
    }
});

uopz_set_hook('pg_query', function ($connection, $query) {
    checkString($query);
});

uopz_set_hook('pg_query_params', function ($connection, $query, $params) {
    for ($i = 0; $i < count($params); $i++) {
        checkString($params[$i]);
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
    checkString($filename);
});

uopz_set_hook('curl_exec', function () {});

uopz_set_hook('fopen', function ($filename, $mode) {
    checkString($filename);
});

uopz_set_hook('file', function ($filename) {
    checkString($filename);
});

# File Upload
uopz_set_hook('move_uploaded_file', function ($from, $to) {
    checkString($from);
    checkString($to);
});

uopz_set_hook('copy', function ($from, $to) {
    checkString($from);
    checkString($to);
});

# File Download
uopz_set_hook('readfile', function ($filename) {
    checkString($filename);
});

# File Deletion
uopz_set_hook('unlink', function ($filename) {
    checkString($filename);
});

?>


