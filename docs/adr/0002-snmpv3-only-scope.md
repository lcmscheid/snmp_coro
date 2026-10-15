# SNMPv3-only scope

Status: Accepted

The library implements **SNMPv3 manager Operations only**: get, getNext, getBulk and set, plus a Walk helper built on getBulk. Explicitly out of scope: SNMPv1/v2c (no community strings anywhere in the code), traps and informs, and MIB-symbolic name resolution. OIDs are numeric dotted strings only.

USM protocols in scope: authentication MD5, SHA-1 (RFC 3414) and SHA-224/256/384/512 (RFC 7860); privacy DES (RFC 3414) and AES-128 (RFC 3826). AES-192/256 are out of scope: they exist only as non-standard Blumenthal/Cisco drafts and only in some net-snmp builds.

This halves the test matrix, deletes the entire community-string concept, and removes the environment-dependent MIB-loading behaviour. That last point is enforced, not just implied: `init_snmp` otherwise loads every MIB installed on the host and logs hundreds of warnings. The library configures net-snmp with `mibs :` (an empty MIB list), with config-file reading disabled, and with persistent state disabled, so nothing is read from or written to `/var/lib/snmp`.

If v1/v2c or traps are ever needed they are additive, not a rework.
