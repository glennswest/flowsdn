# BGP protocol primitives

Framing and OPEN codecs, supported-unicast UPDATE validation, prefix codecs,
strict/lenient error policy, passive transport planning and optional advertised
status projection from spec 15. Independent wire vectors cover malformed
boundaries, capabilities, prefix masking and policy decisions.

This is not a speaker. Session FSM, timers, TCP/MD5 sockets, family negotiation,
full attribute semantics, AS4 conversion, UPDATE splitting, notification data,
RIBs, graceful restart and interoperability suites remain unimplemented. The
API is experimental and unpublished. Successful validation never authorizes
route installation; lenient UPDATE handling is only for export-only sessions.

`decode` consumes one complete frame, reports incomplete input separately, and
leaves coalesced following frames to the caller. `encode` validates framing and
message-specific minimum sizes; callers use the OPEN codec or UPDATE validator
for content. Receivers must bound input buffering independently.
