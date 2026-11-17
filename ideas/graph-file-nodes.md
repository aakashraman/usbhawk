# File nodes in the fleet graph

**Why.** The graph follows sticks, hosts and users. Investigations also ask "where else did this document go?". A
file written to a stick on one host and opened from it on another links the hosts through the file itself.

**Approach.** Add file nodes from session file events (name, size, optional hash) with edges `written_to` /
`read_from` a device on a host; a `file NAME` pivot; a hunt for the same file name and size written on one host and
read on another within a window. Names alone are weak, so a match states its basis (hash > name+size > name).

**Tests.** Fleet-builder hosts with shared and unrelated files; guard against common names (`desktop.ini`,
`Thumbs.db`) linking everything.
