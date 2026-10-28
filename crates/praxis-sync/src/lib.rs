// SPDX-License-Identifier: Apache-2.0
//! PSP/1, the Praxis Sync Protocol (`spec/PROTOCOL.md` §11): `HELLO`/`SUBSCRIBE`/
//! `RECON`/`GET`/`PUT`/`HAVE`/`WANT`/`ERR` messages and range-based set
//! reconciliation over `(ts, id)`. Transport-agnostic: no socket code here, that
//! lives in `praxis-relay` and the CLI/daemon's transport glue.
//!
//! M5-01/M5-02 fill this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
