--TEST--
Bug #79881: Memory leak in openssl_pkey_get_public()
--FILE--
<?php

$cert = "-----BEGIN CERTIFICATE-----
MIIE4jCCAsqgAwIBAgIHBZCisfbbfTANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQG
EwJHQjEPMA0GA1UECAwGTG9uZG9uMRcwFQYDVQQKDA5Hb29nbGUgVUsgTHRkLjEh
MB8GA1UECwwYQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5MSMwIQYDVQQDDBpNZXJn
ZSBEZWxheSBJbnRlcm1lZGlhdGUgMTAeFw0xOTA4MjExNjAyMDhaFw0yMjEwMTMw
NTQ0MjdaMHUxCzAJBgNVBAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xOjA4BgNVBAoM
MUdvb2dsZSBDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kgKFByZWNlcnQgU2lnbmlu
ZykxGTAXBgNVBAUTEDE1NjY0MDMzMjg0MDAyNTMwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDdr1pIlcp/wH42Yb/kxiyx06DKKUO3vZj1Zx7W0kGOPlfP
KroFcSLbCxnrzm1iENVbflBcbeGY1hF3c5cDxs/6bh88Y/5gA1rhP0q1c02Y9yPN
Yo+pi6vfJK41CwsMHTie0U01Ghynzy/683+5tpigp2MccsrPFi5Sk7WMgR78Y6dt
oEH9KZtdbuBlUzyEjnDzR5F7UB3YtrYVOKeYlsYEDmgLZKSMtP9M7/XIc8kUqT1L
VDcB/kk46plGV0b93P+HSPdQcqAUIoqa/zmDnR8XZZGShg1OyJPhB75xCahMr6wL
aXyEFtOwgjDnUZIb5DgpUVwHBq4Xw3QYYmtjk7eVAgMBAAGjbTBrMBgGA1UdJQEB
/wQOMAwGCisGAQQB1nkCBAQwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTp
PAThgC/ChBMtJnCe8v0az6r+xjAdBgNVHQ4EFgQUq3H778kIPz+bmq6to3MFNtGz
qeQwDQYJKoZIhvcNAQEFBQADggIBACYc4ubDw8J7g+AYIS42K2RH/AZ5pf9KAZ+C
OyFkZ5/LV3gNn1CAKFDOyjrGNA6r2yyHZ8TqyKguZqpFLVf1Vn7ll8u38hp7mBFO
/bZGnCdZTtW8Ae8zNQXuFbXoItCk6unGPQsp7/5mHD8nsrqO512zEHuPA+b3v/ZR
tSwkaJZM3W4LhHWiplEoA0F9CCnBKB1W00LDMZTLa4CRdGJlrjwchG0No+ItGrXZ
cc+wLMic6UZ1QrXcvo9efj6/bjLHTee39u4SlIcuL20x97993HZyqP5ZSi+QkKfr
Af441uJNHOFmoClCo6Wb2quNn6F6GvhYxkYcy/CgVP+VOfUBPIF8Ta2KrcI46fAL
Qq6d/SK0GtjlRZME8h48tocBCGvtcZwmZnOQDLd3M51rmfXKB/6y70PjJqiX9ExR
CJzpfafv1OaOqtWre6UofQsEx+jP+P7iGqQo+W9XrufnE7IDso+Za98G5cUIj61a
U6sTKt8w+Ovkxr3UyC/QHdYYJ7nYQfrJ2ml9aAzs1ZlNS8YS0XXpzmpaZhSuhbfM
F6F0Drg3+os4hVFiimUOjspZ4Su2EpsG86hdqJ/HHxTPPfgVlbBP0mexaRco3KVv
pgJ4B+Hh5oOOh9TkR+D3ZKzjc6G2+4nhflYjI AD7B080Jshk6TcII1twXD9qBkvm
9J3nrHWc
-----END CERTIFICATE-----";

$mem1 = memory_get_usage();
$read = openssl_x509_read($cert);
$key = openssl_pkey_get_public($read);
unset($read, $key);
$mem2 = memory_get_usage();
var_dump($mem1 == $mem2);

?>
--EXPECT--
bool(true)
