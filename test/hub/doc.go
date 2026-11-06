// Package hub runs locklog's hub mode end to end in one process, as an
// agent meets it: the MCP tools, the console server (lockkit) with the
// logconsole backend and a real engine session over a log file, and
// lockkit's fake lockhub (hubtest), which decides the tickets. The tests
// need Unix (the engine's file source).
package hub
