# Supplementary Network, Transfer and Template Notes

These user-provided documents are optional historical leads, not sink catalogs or
the primary audit algorithm. Read relevant analysis modules first and discover
the project's actual behavior independently. None of the following API names is
required for discovery or sufficient to establish a vulnerability.

Read on 2026-10-30:

- [Golang SSRF](https://yuque.antfin.com/miantiao.lpc/golangsec/gha0bmeklu9psx5k), doc ID 408553141.
- [Upload/download](https://yuque.antfin.com/miantiao.lpc/golangsec/ev9b9kteq56pm8o9), doc ID 408553140.
- [Template injection](https://yuque.antfin.com/miantiao.lpc/golangsec/dakgvsr2szmp84y2), doc ID 408553143.

## SSRF reference

The document suggests net/http and github.com/carlmjohnson/requests as search leads.
Its sample API names/code must be checked against the actual imported version;
do not treat it as a verified client API catalog. URL/request construction is not
dispatch. Discover custom transports, other clients and delegated fetchers too.

## File transfer reference

The document contains path/filepath and os.Create leads, not a complete transfer
analysis. Filesystem APIs alone do not prove HTTP transfer, confinement failure or
attacker control. Extend source-based discovery to streams, object storage, archives
and actual retrieval/serving paths; apply the backend's real path/key semantics.

## Template reference

The document points to text/template and contains brief field/method access and
Parse examples plus an external article link. These notes do not claim that the
linked article was independently read or verified. Go templates access supplied
objects and exposed capabilities, not all variables in the containing source file.
Verify syntax, export/access rules, registered functions and execution against the
actual engine. Do not copy examples as proof of arbitrary code execution.

No pointer-specific reference was supplied; the unsafe-memory module is independent
guidance, not an assertion that these documents discuss memory safety.
