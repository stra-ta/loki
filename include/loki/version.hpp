#pragma once

// Loki version and format discipline identifiers.
// Bump the format versions whenever an on-disk or schedule-affecting contract changes.

#define LOKI_VERSION_STRING "0.1.0"
#define LOKI_RNG_VERSION 1           // draw order / algorithm identity
#define LOKI_LEDGER_FORMAT_VERSION 1 // events.jsonl record shape
#define LOKI_SCENARIO_VERSION 1      // scenario schema version
