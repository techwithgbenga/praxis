// SPDX-License-Identifier: Apache-2.0
//! `praxisd`: the optional long-running local daemon. gRPC over a Unix domain
//! socket / Windows named pipe with OS-level permissions, single-writer lock, plus
//! an MCP server for agent clients (`docs/ARCHITECTURE.md` §6, `docs/CLI_AND_API.md`
//! §2-3). Agents can only ever create drafts or consult; they cannot sign as the
//! human, close cases, share, or retract.
//!
//! M4-01/M4-11 fill this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

fn main() {
    // TODO(M4-01): UDS/named-pipe gRPC server bootstrap, capability-token auth.
}
