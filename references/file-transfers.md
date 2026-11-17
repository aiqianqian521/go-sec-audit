# Upload, Download and Storage Boundaries

## Discover from behavior

Find actual file/object ingestion and retrieval paths through handlers, multipart
readers, streams, filesystem wrappers, storage SDKs, archive libraries and remote
transfer workers. Model names alone do not establish an upload/download operation.
Include generated artifact/export retrieval, static mounts, remote fetches and
presigned URLs when they participate in the requested scope.

Trace two separate flows:

`caller -> filename/path/object key/resource ID -> resolution/authorization -> read/write/serve`

`caller -> bytes/metadata -> validation/transforms -> storage/extraction/consumer`

For path-traversal findings, state content controllability explicitly. A caller
who controls only the destination path but not the file content (the bytes written
are fixed program output, serialized data or an opaque payload) has arbitrary-path
write, not arbitrary-content write. The two have different impact:
arbitrary-content write can plant executables, cron jobs or credentials;
arbitrary-path write can overwrite, truncate or create files with uncontrolled
content, which may still cause denial of service, corrupt configuration or
interfere with application behavior, but cannot directly execute attacker-chosen
code or data. Trace which fields the caller controls beyond the path that
influence the fixed content and state whether any produce text the attacker can
shape into a meaningful payload. Do not upgrade path-only write to
arbitrary-content write or command execution without demonstrating content control.

Record actual path roots, storage bucket/prefix, owner/tenant and execution identity.
Distinguish file creation from HTTP upload, and object keys from filesystem paths.
A key containing `..` is not filesystem traversal if the storage API treats it
literally; it may still cross an application's logical prefix/tenant boundary.

## Verify concrete boundary failures

### Filesystem targeting

Establish the final resolved path and allowed root for reads, writes, overwrites,
renames and deletion. Inspect URL decoding, path normalization, OS/platform rules,
absolute/relative handling and later transformations. `Clean`, `Join` or `Base`
alone does not prove confinement or a bypass; reason about the actual result.
Do not assume cross-platform path behavior from one host's string conventions.

Consider symlinks/hardlinks and check/use races only when an adversary can control
relevant path components, link creation or mutation. Lexical containment differs
from filesystem containment. Check creation flags and overwrite behavior; an
untrusted filename is a lead, not proof that an attacker can overwrite any file.

### Resource and object authorization

Follow file IDs, object keys, prefixes, buckets and presigned URL requests to the
actual owner/tenant decision. Validate read and write rights separately. A signed
URL can still expose an unauthorized object if signing lacks authorization; its
existence alone is not a defect. Bound its method, object, expiration and exposure.
Relate this to the authorization module without conflating it with path traversal.

### Archive and content consumers

For extraction, check each member's effective destination and supported link or
special-file behavior; follow nested extraction only where implemented. Keep
archive path traversal separate from decompression/resource-exhaustion concerns.
Bounds should apply to actual streamed/decompressed content, not just advertised
length or a parser's memory threshold. A spill-to-disk threshold is not necessarily
a total upload-size limit.

Infer dangerous upload effects from actual later use: execution, parsing, serving,
template loading or privileged configuration consumption. An extension/MIME check
is neither universal protection nor proof of bypass. Uploading a script to inert
object storage does not establish server-side execution. For content served in a
browser, inspect origin, type, disposition and downstream interpretation rather
than calling all uploaded HTML executable on the server.

## Evidence and remediation

For each finding show input control, final target/content flow, relevant guards,
actual consumption and the violated root/ownership/content/resource bound. State
whether the caller controls the path only, the content only, or both. Do not
OS, deployment, link control or execution prerequisites; unknown consumers remain
candidates. Do not infer arbitrary read/write or RCE merely from `os.Create` or a
download function name. Do not upgrade a path-only write to arbitrary-content write
without demonstrating that the caller controls the bytes written or a downstream
consumer that interprets the written content.

Recommend server-controlled storage names/roots, actual containment enforcement,
appropriate link/race protections, object authorization, bounded streaming and
isolated content handling according to the demonstrated defect. Do not substitute
a filename blacklist for the needed boundary. Do not upload, download target data,
extract untrusted archives or overwrite files for verification without authorization.

Optional source context: [io-template-reference-notes.md](io-template-reference-notes.md)
