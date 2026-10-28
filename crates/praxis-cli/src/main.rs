// SPDX-License-Identifier: Apache-2.0
//! The `praxis` command-line interface (`docs/CLI_AND_API.md` §1): `init whoami
//! open decide list show abandon retract export import doctor privacy audit` and
//! the rest of the surface. Offline by default; global flags `--json --no-color
//! --store <path> --offline`; exit codes 0/1/2/3/4/5 per the spec.
//!
//! M2-06 fills this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

fn main() {
    // TODO(M2-06): argument parsing and subcommand dispatch over `praxis_core`.
}
