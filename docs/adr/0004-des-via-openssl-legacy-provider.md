# DES privacy via an OpenSSL legacy provider provisioned by the repo

Status: Superseded by ADR 0008

## Original decision

net-snmp 5.9 does privacy through OpenSSL, and OpenSSL 3 moved DES to the legacy provider. On the original dev box (OpenSSL 3.6.5) DES was unavailable by default. Rather than dropping DES from the credential matrix, the repo carried a `tests/openssl.cnf` that activated the default and legacy providers, and CTest pointed `OPENSSL_CONF` at it.

## Why it was withdrawn

On the only supported platform, Ubuntu 26.04 (OpenSSL 3.5.5, net-snmp 5.9.4; ADR 0008), MD5+DES authPriv works without the legacy provider. The full integration suite, including the MD5+DES user, passes with no `OPENSSL_CONF`, so the config file and the CTest environment were removed.

If DES fails on another OpenSSL build, the fix is outside the repo: activate the legacy provider in that system's OpenSSL configuration.

## Still in force

A finding from the original probe still applies to the test agent: `rouser`/`rwuser` lines default to requiring *auth*, so the noAuthNoPriv test user must be granted with an explicit `noauth` level in the test `snmpd.conf`.
