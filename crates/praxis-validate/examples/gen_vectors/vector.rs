// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for writing `*.vec.json` files (`spec/test-vectors/README.md`).

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value as Json};

/// The repo root, relative to this example binary's `CARGO_MANIFEST_DIR`
/// (`crates/praxis-validate`).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `spec/test-vectors/<id>.vec.json`.
pub fn vector_path(id: &str) -> PathBuf {
    repo_root()
        .join("spec/test-vectors")
        .join(format!("{id}.vec.json"))
}

/// Writes one vector file, per `spec/test-vectors/README.md`'s format.
pub fn write_vector(id: &str, spec: &str, description: &str, input: &Json, expected: &Json) {
    let doc = json!({
        "id": id,
        "spec": spec,
        "description": description,
        "input": input,
        "expected": expected,
    });
    let path = vector_path(id);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

/// Lowercase hex, matching `spec/test-vectors/README.md`'s "byte strings are
/// lowercase hex" rule — the one place our real types' default JSON
/// serialization (byte arrays as arrays of numbers, via `serde_bytes`)
/// deliberately isn't reused for vectors.
pub fn hex(bytes: &[u8]) -> Json {
    Json::String(hex::encode(bytes))
}

/// A rejected-input vector's `expected` field: `{"error": "<code>"}`.
pub fn expected_error(code: &str) -> Json {
    json!({ "error": code })
}

/// Removes every existing vector under `spec/test-vectors/<category>/` before
/// regenerating it, so a renamed/removed vector doesn't linger as a stale file.
pub fn clean_category(category: &str) {
    let dir = repo_root().join("spec/test-vectors").join(category);
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
}

#[allow(dead_code)]
pub fn exists(id: &str) -> bool {
    Path::new(&vector_path(id)).exists()
}
