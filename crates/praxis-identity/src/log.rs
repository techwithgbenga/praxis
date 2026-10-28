// SPDX-License-Identifier: Apache-2.0
//! The identity log state machine (`spec/PROTOCOL.md` §4; byte-level and
//! signing-authority gaps resolved by `spec/pips/0003-identity-log-semantics.md`).

use std::collections::BTreeMap;

use praxis_crypto::{verify_object, PublicKey};
use praxis_types::{Did, IdContent, IdOp, KeyEntry, KeyRole, Kind, Object, Ts};

use crate::error::IdentityError;

/// The fixed, non-cryptographic placeholder for `id-genesis.author`
/// (`spec/pips/0004-genesis-author-sentinel.md`): the real DID cannot be
/// known until after the genesis object is signed (it is derived from the
/// object's own CID), so this field cannot literally hold it.
pub const GENESIS_AUTHOR_SENTINEL: &str = "did:praxis:selfselfselfselfself";

#[derive(Debug, Clone)]
struct KeyRecord {
    entry: KeyEntry,
    /// Set when revoked (`id-revoke.revoke.effective`) or when this key was
    /// root and a later `id-rotate` retired it (PIP-0003): the key is
    /// invalid for every purpose at any `ts >= retired_at`.
    retired_at: Option<Ts>,
    compromised_since: Option<Ts>,
}

/// One practitioner's identity log: the evolving set of keys introduced by
/// `id-genesis`/`id-rotate`/`id-delegate` and retired by `id-revoke` or by a
/// later rotation, plus the authorization queries built on top of it
/// (`spec/PROTOCOL.md` §4.4, "key authorization" per `docs/ARCHITECTURE.md` §3).
///
/// Does not itself check causal (`prev`) ordering across an author's whole
/// object graph, or kind-specific case-lifecycle rules — those are
/// `praxis-validate`'s (M1-07), one layer up. This log does enforce that
/// identity objects are applied to it in non-decreasing `ts` order, since
/// "key valid at time T" is only meaningful for a log built up to at least T.
#[derive(Debug, Clone)]
pub struct IdentityLog {
    did: Did,
    keys: BTreeMap<praxis_types::Kid, KeyRecord>,
    current_root_kid: praxis_types::Kid,
    last_ts: Ts,
}

impl IdentityLog {
    /// Starts a new identity log from its `id-genesis` object.
    ///
    /// Verifies that the object is signed by one of its own listed keys with
    /// `role: root` (PIP-0003), then derives the log's `did` from this
    /// object's own CID (`spec/PROTOCOL.md` §4.1, PIP-0003).
    ///
    /// # Errors
    /// See [`IdentityError`].
    ///
    /// # Panics
    /// Never: a `Cid`'s `Display` output is always a valid `Did` suffix (verified
    /// in `praxis-types`; see `spec/pips/0003-identity-log-semantics.md`).
    pub fn genesis(object: &Object, content: &IdContent) -> Result<Self, IdentityError> {
        if object.kind != Kind::IdGenesis || content.op != IdOp::Genesis {
            return Err(IdentityError::KindOpMismatch);
        }
        if object.author.as_str() != GENESIS_AUTHOR_SENTINEL {
            return Err(IdentityError::InvalidGenesisAuthor);
        }
        let entries = content.keys.as_deref().unwrap_or(&[]);
        if entries.is_empty() {
            return Err(IdentityError::GenesisHasNoKeys);
        }
        let signer_entry = entries
            .iter()
            .find(|k| k.kid == object.signer && k.role == KeyRole::Root)
            .ok_or_else(|| IdentityError::UnauthorizedSigner(object.signer.clone(), object.ts))?;
        verify_signature(object, signer_entry)?;

        let cid = praxis_types::object_id(object)?;
        let did = Did::new(format!("did:praxis:{cid}"))
            .expect("a freshly computed Cid's Display always yields a valid Did suffix");

        let mut log = Self {
            did,
            keys: BTreeMap::new(),
            current_root_kid: signer_entry.kid.clone(),
            last_ts: object.ts,
        };
        for entry in entries {
            log.insert_new_key(entry.clone())?;
        }
        Ok(log)
    }

    /// Applies an `id-rotate`/`id-delegate`/`id-revoke` object to this log.
    ///
    /// # Errors
    /// See [`IdentityError`]. In particular, [`IdentityError::UnexpectedGenesis`]
    /// if `content.op` is `Genesis` (a log has exactly one, via [`Self::genesis`]).
    pub fn apply(&mut self, object: &Object, content: &IdContent) -> Result<(), IdentityError> {
        if object.ts < self.last_ts {
            return Err(IdentityError::TsNotMonotonic(object.ts, self.last_ts));
        }
        match content.op {
            IdOp::Genesis => Err(IdentityError::UnexpectedGenesis),
            IdOp::Rotate => self.apply_rotate(object, content),
            IdOp::Delegate => self.apply_delegate(object, content),
            IdOp::Revoke => self.apply_revoke(object, content),
        }
    }

    fn apply_rotate(&mut self, object: &Object, content: &IdContent) -> Result<(), IdentityError> {
        if object.kind != Kind::IdRotate {
            return Err(IdentityError::KindOpMismatch);
        }
        let signer_entry = self.require_root_or_recovery_signer(object)?;
        verify_signature(object, &signer_entry)?;

        let entries = content.keys.as_deref().unwrap_or(&[]);
        let [new_root] = entries else {
            return Err(IdentityError::InvalidPayload(
                "id-rotate must list exactly one key",
            ));
        };
        if new_root.role != KeyRole::Root {
            return Err(IdentityError::InvalidPayload(
                "id-rotate's key must have role root",
            ));
        }

        // PIP-0003: retire the previous root key as of this rotation, for every purpose.
        if let Some(old_root) = self.keys.get_mut(&self.current_root_kid) {
            old_root.retired_at = Some(object.ts);
        }
        self.insert_new_key(new_root.clone())?;
        self.current_root_kid = new_root.kid.clone();
        self.last_ts = object.ts;
        Ok(())
    }

    fn apply_delegate(
        &mut self,
        object: &Object,
        content: &IdContent,
    ) -> Result<(), IdentityError> {
        if object.kind != Kind::IdDelegate {
            return Err(IdentityError::KindOpMismatch);
        }
        let signer_entry = self.require_root_or_recovery_signer(object)?;
        verify_signature(object, &signer_entry)?;

        let entries = content.keys.as_deref().unwrap_or(&[]);
        if entries.is_empty() {
            return Err(IdentityError::InvalidPayload(
                "id-delegate must list at least one key",
            ));
        }
        for entry in entries {
            self.insert_new_key(entry.clone())?;
        }
        self.last_ts = object.ts;
        Ok(())
    }

    fn apply_revoke(&mut self, object: &Object, content: &IdContent) -> Result<(), IdentityError> {
        if object.kind != Kind::IdRevoke {
            return Err(IdentityError::KindOpMismatch);
        }
        let revoke = content
            .revoke
            .as_ref()
            .ok_or(IdentityError::InvalidPayload(
                "id-revoke must carry a revoke record",
            ))?;

        // PIP-0003: root/recovery may revoke anyone; a key may also revoke itself.
        if object.signer == revoke.kid {
            let record = self
                .keys
                .get(&object.signer)
                .ok_or_else(|| IdentityError::UnknownSigner(object.signer.clone()))?;
            Self::check_validity_window(record, object.ts).map_err(|()| {
                IdentityError::UnauthorizedSigner(object.signer.clone(), object.ts)
            })?;
            verify_signature(object, &record.entry.clone())?;
        } else {
            let signer_entry = self.require_root_or_recovery_signer(object)?;
            verify_signature(object, &signer_entry)?;
        }

        let target = self
            .keys
            .get_mut(&revoke.kid)
            .ok_or_else(|| IdentityError::UnknownRevokeTarget(revoke.kid.clone()))?;
        target.retired_at = Some(revoke.effective);
        target.compromised_since = revoke.compromised_since;
        self.last_ts = object.ts;
        Ok(())
    }

    fn insert_new_key(&mut self, entry: KeyEntry) -> Result<(), IdentityError> {
        if self.keys.contains_key(&entry.kid) {
            return Err(IdentityError::DuplicateKid(entry.kid));
        }
        let kid = entry.kid.clone();
        self.keys.insert(
            kid,
            KeyRecord {
                entry,
                retired_at: None,
                compromised_since: None,
            },
        );
        Ok(())
    }

    /// Checks that the object's claimed signer is currently (at `object.ts`)
    /// a valid root or recovery key, and returns its entry.
    fn require_root_or_recovery_signer(&self, object: &Object) -> Result<KeyEntry, IdentityError> {
        let record = self
            .keys
            .get(&object.signer)
            .ok_or_else(|| IdentityError::UnknownSigner(object.signer.clone()))?;
        if !matches!(record.entry.role, KeyRole::Root | KeyRole::Recovery) {
            return Err(IdentityError::UnauthorizedSigner(
                object.signer.clone(),
                object.ts,
            ));
        }
        Self::check_validity_window(record, object.ts)
            .map_err(|()| IdentityError::UnauthorizedSigner(object.signer.clone(), object.ts))?;
        Ok(record.entry.clone())
    }

    /// `not_before <= at`, `at <= not_after` (if bounded), and not retired as of `at`.
    fn check_validity_window(record: &KeyRecord, at: Ts) -> Result<(), ()> {
        if at < record.entry.not_before {
            return Err(());
        }
        if let Some(not_after) = record.entry.not_after {
            if at > not_after {
                return Err(());
            }
        }
        if let Some(retired_at) = record.retired_at {
            if at >= retired_at {
                return Err(());
            }
        }
        Ok(())
    }

    /// This identity's stable `did:praxis:...` identifier.
    #[must_use]
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// Whether `kid` was authorized, at time `at`, to sign an object of
    /// `for_kind` (or any kind, if `for_kind` is `None`) — `spec/PROTOCOL.md`
    /// §4.4's "signer key was authorized by the identity log at the
    /// object's `ts`", for ordinary (non-identity) objects. Identity
    /// objects' own signer authorization is checked internally by
    /// [`Self::genesis`]/[`Self::apply`].
    #[must_use]
    pub fn is_authorized(&self, kid: &praxis_types::Kid, at: Ts, for_kind: Option<Kind>) -> bool {
        let Some(record) = self.keys.get(kid) else {
            return false;
        };
        if Self::check_validity_window(record, at).is_err() {
            return false;
        }
        if let Some(kind) = for_kind {
            if let Some(scope) = &record.entry.scope {
                if !scope.contains(&kind) {
                    return false;
                }
            }
        }
        true
    }

    /// The role `kid` held at time `at`, if it was a known (not necessarily
    /// currently valid) key at all. Diagnostic/UI use (e.g. `praxis keys
    /// list`); [`Self::is_authorized`] is the authoritative check.
    #[must_use]
    pub fn role_at(&self, kid: &praxis_types::Kid, at: Ts) -> Option<KeyRole> {
        let record = self.keys.get(kid)?;
        (record.entry.not_before <= at).then_some(record.entry.role)
    }

    /// Whether `kid` has a recorded `compromised_since` (`spec/PROTOCOL.md`
    /// §4.5) — informational, for scoring/display; does not by itself affect
    /// [`Self::is_authorized`], which only looks at the validity window.
    #[must_use]
    pub fn compromised_since(&self, kid: &praxis_types::Kid) -> Option<Ts> {
        self.keys.get(kid)?.compromised_since
    }
}

fn verify_signature(object: &Object, entry: &KeyEntry) -> Result<(), IdentityError> {
    let pubkey = PublicKey::from_bytes(&entry.public_key)?;
    let bytes = object.canonical_signing_bytes()?;
    verify_object(&pubkey, &bytes, object.sig.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use praxis_crypto::SecretKey;
    use praxis_types::{
        Body, Did, Ed25519Alg, FormatVersion, Kid as KeyId, PlainBody, Revocation, Sig, Suite,
        Value,
    };
    use proptest::prelude::*;

    use super::*;

    fn key_entry(
        kid: &str,
        role: KeyRole,
        secret: &SecretKey,
        not_before: u64,
        not_after: Option<u64>,
    ) -> KeyEntry {
        KeyEntry {
            kid: KeyId::new(kid).unwrap(),
            alg: Ed25519Alg,
            public_key: secret.public_key().to_bytes(),
            role,
            enc_pub: None,
            not_before: Ts::from_millis(not_before),
            not_after: not_after.map(Ts::from_millis),
            scope: None,
        }
    }

    fn signed_object(
        kind: Kind,
        signer_kid: &str,
        author: &str,
        ts: u64,
        secret: &SecretKey,
    ) -> Object {
        let mut obj = Object {
            v: FormatVersion,
            kind,
            case: None,
            prev: vec![],
            author: Did::new(author).unwrap(),
            signer: KeyId::new(signer_kid).unwrap(),
            ts: Ts::from_millis(ts),
            suite: Suite::Pxs1,
            body: Body::Plain(PlainBody {
                plain: Value::Null,
                salt: [0u8; 16],
                pad: None,
            }),
            sig: Sig::new([0u8; 64]),
            crit: None,
            unknown: BTreeMap::new(),
        };
        let bytes = obj.canonical_signing_bytes().unwrap();
        obj.sig = Sig::new(praxis_crypto::sign_object(secret, &bytes));
        obj
    }

    fn genesis_content(keys: Vec<KeyEntry>) -> IdContent {
        IdContent {
            op: IdOp::Genesis,
            keys: Some(keys),
            revoke: None,
        }
    }
    fn rotate_content(key: KeyEntry) -> IdContent {
        IdContent {
            op: IdOp::Rotate,
            keys: Some(vec![key]),
            revoke: None,
        }
    }
    fn delegate_content(keys: Vec<KeyEntry>) -> IdContent {
        IdContent {
            op: IdOp::Delegate,
            keys: Some(keys),
            revoke: None,
        }
    }
    fn revoke_content(kid: &str, effective: u64, compromised_since: Option<u64>) -> IdContent {
        IdContent {
            op: IdOp::Revoke,
            keys: None,
            revoke: Some(Revocation {
                kid: KeyId::new(kid).unwrap(),
                effective: Ts::from_millis(effective),
                compromised_since: compromised_since.map(Ts::from_millis),
            }),
        }
    }

    fn fresh_log_with_root(root: &SecretKey) -> (IdentityLog, Did) {
        let content = genesis_content(vec![key_entry("root-1", KeyRole::Root, root, 0, None)]);
        let object = signed_object(Kind::IdGenesis, "root-1", GENESIS_AUTHOR_SENTINEL, 0, root);
        let log = IdentityLog::genesis(&object, &content).unwrap();
        let did = log.did().clone();
        (log, did)
    }

    #[test]
    fn genesis_establishes_identity_and_root_key() {
        let root = SecretKey::generate();
        let (log, _did) = fresh_log_with_root(&root);
        let root_kid = KeyId::new("root-1").unwrap();
        assert!(log.is_authorized(&root_kid, Ts::from_millis(0), None));
        assert_eq!(
            log.role_at(&root_kid, Ts::from_millis(0)),
            Some(KeyRole::Root)
        );
    }

    #[test]
    fn genesis_rejects_wrong_author_sentinel() {
        let root = SecretKey::generate();
        let content = genesis_content(vec![key_entry("root-1", KeyRole::Root, &root, 0, None)]);
        let object = signed_object(
            Kind::IdGenesis,
            "root-1",
            "did:praxis:bbbbbbbbbbbbbbbbbbbb",
            0,
            &root,
        );
        assert!(matches!(
            IdentityLog::genesis(&object, &content),
            Err(IdentityError::InvalidGenesisAuthor)
        ));
    }

    #[test]
    fn genesis_rejects_signer_not_listed_as_root() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let content = genesis_content(vec![
            key_entry("root-1", KeyRole::Root, &root, 0, None),
            key_entry("device-1", KeyRole::Device, &device, 0, None),
        ]);
        let object = signed_object(
            Kind::IdGenesis,
            "device-1",
            GENESIS_AUTHOR_SENTINEL,
            0,
            &device,
        );
        assert!(matches!(
            IdentityLog::genesis(&object, &content),
            Err(IdentityError::UnauthorizedSigner(_, _))
        ));
    }

    #[test]
    fn genesis_rejects_bad_signature() {
        let root = SecretKey::generate();
        let impostor = SecretKey::generate();
        let content = genesis_content(vec![key_entry("root-1", KeyRole::Root, &root, 0, None)]);
        // Claims signer=root-1 but is actually signed by a different key.
        let object = signed_object(
            Kind::IdGenesis,
            "root-1",
            GENESIS_AUTHOR_SENTINEL,
            0,
            &impostor,
        );
        assert!(matches!(
            IdentityLog::genesis(&object, &content),
            Err(IdentityError::InvalidSignature(_))
        ));
    }

    #[test]
    fn rotation_retires_old_root_and_activates_new_root() {
        let root1 = SecretKey::generate();
        let root2 = SecretKey::generate();
        let (mut log, did) = fresh_log_with_root(&root1);

        let rotate = rotate_content(key_entry("root-2", KeyRole::Root, &root2, 1000, None));
        let rotate_obj = signed_object(Kind::IdRotate, "root-1", did.as_str(), 1000, &root1);
        log.apply(&rotate_obj, &rotate).unwrap();

        let root1_kid = KeyId::new("root-1").unwrap();
        let root2_kid = KeyId::new("root-2").unwrap();
        assert!(log.is_authorized(&root1_kid, Ts::from_millis(999), None));
        assert!(!log.is_authorized(&root1_kid, Ts::from_millis(1000), None));
        assert!(log.is_authorized(&root2_kid, Ts::from_millis(1000), None));
        assert!(!log.is_authorized(&root2_kid, Ts::from_millis(999), None));
    }

    #[test]
    fn delegate_adds_device_key_with_scope() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let (mut log, did) = fresh_log_with_root(&root);

        let mut device_entry = key_entry("device-1", KeyRole::Device, &device, 100, None);
        device_entry.scope = Some(vec![Kind::Decision, Kind::Claims]);
        let delegate = delegate_content(vec![device_entry]);
        let delegate_obj = signed_object(Kind::IdDelegate, "root-1", did.as_str(), 100, &root);
        log.apply(&delegate_obj, &delegate).unwrap();

        let device_kid = KeyId::new("device-1").unwrap();
        assert!(log.is_authorized(&device_kid, Ts::from_millis(200), Some(Kind::Decision)));
        assert!(!log.is_authorized(&device_kid, Ts::from_millis(200), Some(Kind::Open)));
    }

    #[test]
    fn device_key_cannot_delegate_or_revoke() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let other = SecretKey::generate();
        let (mut log, did) = fresh_log_with_root(&root);

        log.apply(
            &signed_object(Kind::IdDelegate, "root-1", did.as_str(), 100, &root),
            &delegate_content(vec![key_entry(
                "device-1",
                KeyRole::Device,
                &device,
                100,
                None,
            )]),
        )
        .unwrap();

        let bad_delegate = delegate_content(vec![key_entry(
            "device-2",
            KeyRole::Device,
            &other,
            200,
            None,
        )]);
        let bad_obj = signed_object(Kind::IdDelegate, "device-1", did.as_str(), 200, &device);
        assert!(matches!(
            log.apply(&bad_obj, &bad_delegate),
            Err(IdentityError::UnauthorizedSigner(_, _))
        ));
    }

    #[test]
    fn self_revocation_is_allowed_but_cross_device_revocation_is_not() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let other_device = SecretKey::generate();

        let (mut log, did) = fresh_log_with_root(&root);
        log.apply(
            &signed_object(Kind::IdDelegate, "root-1", did.as_str(), 100, &root),
            &delegate_content(vec![
                key_entry("device-1", KeyRole::Device, &device, 100, None),
                key_entry("device-2", KeyRole::Device, &other_device, 100, None),
            ]),
        )
        .unwrap();

        // device-1 revokes itself: allowed.
        let self_revoke_obj = signed_object(Kind::IdRevoke, "device-1", did.as_str(), 200, &device);
        log.apply(&self_revoke_obj, &revoke_content("device-1", 200, None))
            .unwrap();
        assert!(!log.is_authorized(&KeyId::new("device-1").unwrap(), Ts::from_millis(200), None));

        // A fresh log where device-2 instead tries to revoke device-1 (not itself,
        // not root/recovery): must fail.
        let (mut log2, did2) = fresh_log_with_root(&root);
        log2.apply(
            &signed_object(Kind::IdDelegate, "root-1", did2.as_str(), 100, &root),
            &delegate_content(vec![
                key_entry("device-1", KeyRole::Device, &device, 100, None),
                key_entry("device-2", KeyRole::Device, &other_device, 100, None),
            ]),
        )
        .unwrap();
        let cross_revoke_obj = signed_object(
            Kind::IdRevoke,
            "device-2",
            did2.as_str(),
            200,
            &other_device,
        );
        assert!(matches!(
            log2.apply(&cross_revoke_obj, &revoke_content("device-1", 200, None)),
            Err(IdentityError::UnauthorizedSigner(_, _))
        ));
    }

    #[test]
    fn revoked_key_is_unauthorized_from_effective_time_onward() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let (mut log, did) = fresh_log_with_root(&root);

        log.apply(
            &signed_object(Kind::IdDelegate, "root-1", did.as_str(), 100, &root),
            &delegate_content(vec![key_entry(
                "device-1",
                KeyRole::Device,
                &device,
                100,
                None,
            )]),
        )
        .unwrap();
        log.apply(
            &signed_object(Kind::IdRevoke, "root-1", did.as_str(), 500, &root),
            &revoke_content("device-1", 500, Some(400)),
        )
        .unwrap();

        let device_kid = KeyId::new("device-1").unwrap();
        assert!(log.is_authorized(&device_kid, Ts::from_millis(499), None));
        assert!(!log.is_authorized(&device_kid, Ts::from_millis(500), None));
        assert_eq!(
            log.compromised_since(&device_kid),
            Some(Ts::from_millis(400))
        );
    }

    #[test]
    fn backdating_attempt_is_rejected_by_ts_monotonicity() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let (mut log, did) = fresh_log_with_root(&root);

        log.apply(
            &signed_object(Kind::IdDelegate, "root-1", did.as_str(), 1000, &root),
            &delegate_content(vec![key_entry(
                "device-1",
                KeyRole::Device,
                &device,
                1000,
                None,
            )]),
        )
        .unwrap();

        // A compromised root key tries to backdate a later event to ts=500, before
        // the already-applied ts=1000 event, to make it look older than it is.
        let backdated_obj = signed_object(Kind::IdDelegate, "root-1", did.as_str(), 500, &root);
        let backdated = delegate_content(vec![key_entry(
            "device-2",
            KeyRole::Device,
            &SecretKey::generate(),
            500,
            None,
        )]);
        assert!(matches!(
            log.apply(&backdated_obj, &backdated),
            Err(IdentityError::TsNotMonotonic(_, _))
        ));
    }

    #[test]
    fn duplicate_kid_is_rejected() {
        let root = SecretKey::generate();
        let device = SecretKey::generate();
        let (mut log, did) = fresh_log_with_root(&root);

        log.apply(
            &signed_object(Kind::IdDelegate, "root-1", did.as_str(), 100, &root),
            &delegate_content(vec![key_entry(
                "device-1",
                KeyRole::Device,
                &device,
                100,
                None,
            )]),
        )
        .unwrap();

        let dup_obj = signed_object(Kind::IdDelegate, "root-1", did.as_str(), 200, &root);
        let dup = delegate_content(vec![key_entry(
            "device-1",
            KeyRole::Device,
            &SecretKey::generate(),
            200,
            None,
        )]);
        assert!(matches!(
            log.apply(&dup_obj, &dup),
            Err(IdentityError::DuplicateKid(_))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn is_authorized_matches_the_validity_window(
            not_before in 0u64..1000,
            window in 0u64..1000,
            query_offset in -500i64..1500,
        ) {
            let not_after = not_before + window;
            let root = SecretKey::generate();
            let device = SecretKey::generate();
            let (mut log, did) = fresh_log_with_root(&root);

            let entry = key_entry("device-1", KeyRole::Device, &device, not_before, Some(not_after));
            log.apply(
                &signed_object(Kind::IdDelegate, "root-1", did.as_str(), not_before, &root),
                &delegate_content(vec![entry]),
            )
            .unwrap();

            let query_ts = u64::try_from((i64::try_from(not_before).unwrap() + query_offset).max(0)).unwrap();
            let expected = query_ts >= not_before && query_ts <= not_after;
            let actual = log.is_authorized(&KeyId::new("device-1").unwrap(), Ts::from_millis(query_ts), None);
            prop_assert_eq!(actual, expected);
        }
    }
}
