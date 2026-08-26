//! POSIX ACL inheritance for newly created inodes.
//!
//! Negotiating `FUSE_POSIX_ACL` (see `LchfsFilesystem::init`) hands the
//! kernel responsibility for ACL-aware *permission checking*, but hands
//! userspace responsibility for two things the kernel would otherwise do
//! itself: applying the umask, and inheriting a directory's default ACL onto
//! the objects created inside it. Without the second, `setfacl -d` would
//! appear to work while silently affecting nothing.
//!
//! This module is a direct translation of the kernel's `posix_acl_create` /
//! `posix_acl_create_masq` (fs/posix_acl.c), which is the definition of
//! correct here -- deliberately not a reinterpretation. It lives in
//! `lchfs-fuse` rather than `lchfs-store` because it is Linux ACL protocol
//! handling (a binary xattr encoding plus the semantics the kernel expects
//! of a FUSE server), not storage or DAG logic; §5a's boundary is about
//! keeping FUSE types and protocol concerns out of the engine, and this is
//! squarely a protocol concern.

/// `system.posix_acl_access` -- the ACL that governs access to an object.
pub const ACCESS_XATTR: &str = "system.posix_acl_access";
/// `system.posix_acl_default` -- a directory's template for what its
/// children inherit. Meaningless on non-directories.
pub const DEFAULT_XATTR: &str = "system.posix_acl_default";

const VERSION: u32 = 2;

const TAG_USER_OBJ: u16 = 0x01;
const TAG_USER: u16 = 0x02;
const TAG_GROUP_OBJ: u16 = 0x04;
const TAG_GROUP: u16 = 0x08;
const TAG_MASK: u16 = 0x10;
const TAG_OTHER: u16 = 0x20;

const S_IRWXU: u32 = 0o700;
const S_IRWXG: u32 = 0o070;
const S_IRWXO: u32 = 0o007;
const S_IRWXUGO: u32 = 0o777;

/// One ACL entry, matching the on-disk `posix_acl_xattr_entry`:
/// `{ __le16 e_tag; __le16 e_perm; __le32 e_id; }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub tag: u16,
    pub perm: u16,
    pub id: u32,
}

const ENTRY_LEN: usize = 8;
const HEADER_LEN: usize = 4;

/// Decodes the binary xattr form. Returns `None` for anything malformed --
/// a corrupt or foreign-version ACL is treated as "no ACL" rather than
/// guessed at, since the alternative is inventing permissions.
pub fn parse(bytes: &[u8]) -> Option<Vec<Entry>> {
    if bytes.len() < HEADER_LEN || !(bytes.len() - HEADER_LEN).is_multiple_of(ENTRY_LEN) {
        return None;
    }
    if u32::from_le_bytes(bytes[0..4].try_into().ok()?) != VERSION {
        return None;
    }
    let mut entries = Vec::with_capacity((bytes.len() - HEADER_LEN) / ENTRY_LEN);
    for chunk in bytes[HEADER_LEN..].chunks_exact(ENTRY_LEN) {
        entries.push(Entry {
            tag: u16::from_le_bytes(chunk[0..2].try_into().ok()?),
            perm: u16::from_le_bytes(chunk[2..4].try_into().ok()?),
            id: u32::from_le_bytes(chunk[4..8].try_into().ok()?),
        });
    }
    Some(entries)
}

pub fn serialize(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + entries.len() * ENTRY_LEN);
    out.extend_from_slice(&VERSION.to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        out.extend_from_slice(&e.id.to_le_bytes());
    }
    out
}

/// The kernel's `posix_acl_create_masq`: folds `mode` into the cloned ACL
/// and the ACL back into `mode`, so the two agree. Returns the adjusted mode
/// and whether the result still needs a stored ACL (`not_equiv`) -- an ACL
/// with no named user/group and no mask carries no information the mode bits
/// don't already, so storing it would be pure overhead.
fn create_masq(entries: &mut [Entry], mode: u32) -> Option<(u32, bool)> {
    let mut mode_bits = mode;
    let mut not_equiv = false;
    let mut group_obj_idx = None;
    let mut mask_idx = None;

    for (i, e) in entries.iter_mut().enumerate() {
        match e.tag {
            TAG_USER_OBJ => {
                e.perm &= ((mode_bits >> 6) | !S_IRWXO) as u16;
                mode_bits &= ((e.perm as u32) << 6) | !S_IRWXU;
            }
            TAG_USER | TAG_GROUP => not_equiv = true,
            TAG_GROUP_OBJ => group_obj_idx = Some(i),
            TAG_OTHER => {
                e.perm &= (mode_bits | !S_IRWXO) as u16;
                mode_bits &= (e.perm as u32) | !S_IRWXO;
            }
            TAG_MASK => {
                mask_idx = Some(i);
                not_equiv = true;
            }
            _ => return None,
        }
    }

    // The mask entry, when present, stands in for the group-object entry
    // when reconciling the middle permission triad.
    if let Some(i) = mask_idx {
        let e = &mut entries[i];
        e.perm &= ((mode_bits >> 3) | !S_IRWXO) as u16;
        mode_bits &= ((e.perm as u32) << 3) | !S_IRWXG;
    } else {
        // A default ACL with no mask must still have a group-object entry;
        // one without is malformed, and the kernel returns EIO here too.
        let i = group_obj_idx?;
        let e = &mut entries[i];
        e.perm &= ((mode_bits >> 3) | !S_IRWXO) as u16;
        mode_bits &= ((e.perm as u32) << 3) | !S_IRWXG;
    }

    Some(((mode & !S_IRWXUGO) | (mode_bits & S_IRWXUGO), not_equiv))
}

/// What a newly created object should end up with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inherited {
    /// The mode to create with. Note the umask has deliberately *not* been
    /// applied when a default ACL exists -- see [`inherit`].
    pub mode: u32,
    /// `system.posix_acl_access` to set on the new object, if the inherited
    /// ACL carries anything the mode bits cannot express.
    pub access: Option<Vec<u8>>,
    /// `system.posix_acl_default` to set, i.e. the parent's default ACL
    /// passed straight down. Directories only.
    pub default: Option<Vec<u8>>,
}

/// Computes what a new child of a directory inherits, mirroring the kernel's
/// `posix_acl_create`.
///
/// `parent_default` is the parent directory's raw `system.posix_acl_default`
/// xattr, or `None` if it has none.
///
/// The umask rule is the subtle part and is the kernel's, not ours: when the
/// parent has a default ACL the umask is **not** applied, because the default
/// ACL is the more specific statement of intent; only when there is no
/// default ACL does the umask apply. Getting this backwards would silently
/// widen or narrow permissions on every create inside an ACL'd directory.
pub fn inherit(parent_default: Option<&[u8]>, mode: u32, umask: u32, is_dir: bool) -> Inherited {
    let Some(parsed) = parent_default.and_then(parse) else {
        return Inherited { mode: mode & !umask, access: None, default: None };
    };
    if parsed.is_empty() {
        return Inherited { mode: mode & !umask, access: None, default: None };
    }

    // Only directories carry a default ACL onward; a regular file inherits
    // an access ACL but has no children to pass anything to.
    let default = is_dir.then(|| serialize(&parsed));

    let mut access = parsed;
    match create_masq(&mut access, mode) {
        Some((new_mode, not_equiv)) => Inherited {
            mode: new_mode,
            access: not_equiv.then(|| serialize(&access)),
            default,
        },
        // Malformed default ACL: fall back to plain umask behaviour rather
        // than creating with permissions derived from something we could not
        // interpret.
        None => Inherited { mode: mode & !umask, access: None, default },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: u16, perm: u16, id: u32) -> Entry {
        Entry { tag, perm, id }
    }

    /// A minimal, well-formed default ACL granting a named user rwx, which
    /// is what `setfacl -d -m u:someone:rwx` produces.
    fn default_acl_with_named_user() -> Vec<u8> {
        serialize(&[
            entry(TAG_USER_OBJ, 7, u32::MAX),
            entry(TAG_USER, 7, 1234),
            entry(TAG_GROUP_OBJ, 5, u32::MAX),
            entry(TAG_MASK, 7, u32::MAX),
            entry(TAG_OTHER, 5, u32::MAX),
        ])
    }

    #[test]
    fn parse_round_trips_serialize() {
        let entries = vec![entry(TAG_USER_OBJ, 6, u32::MAX), entry(TAG_OTHER, 4, u32::MAX)];
        assert_eq!(parse(&serialize(&entries)).unwrap(), entries);
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0, 0, 0]).is_none());
        // Right shape, wrong version.
        assert!(parse(&[9, 0, 0, 0]).is_none());
        // Valid version, truncated entry.
        assert!(parse(&[2, 0, 0, 0, 1, 0, 6]).is_none());
        // Unknown tag is caught later, by create_masq, not by parse.
        assert!(parse(&serialize(&[entry(0x99, 7, 0)])).is_some());
    }

    #[test]
    fn no_default_acl_applies_the_umask() {
        let got = inherit(None, 0o666, 0o022, false);
        assert_eq!(got.mode, 0o644);
        assert!(got.access.is_none());
        assert!(got.default.is_none());
    }

    #[test]
    fn a_malformed_default_acl_falls_back_to_umask() {
        let got = inherit(Some(&[1, 2, 3]), 0o666, 0o077, false);
        assert_eq!(got.mode, 0o600);
        assert!(got.access.is_none());
    }

    /// The umask must be ignored when a default ACL is present -- the ACL is
    /// the more specific statement of intent.
    #[test]
    fn a_default_acl_suppresses_the_umask() {
        let acl = default_acl_with_named_user();
        let got = inherit(Some(&acl), 0o666, 0o077, false);
        // With umask 077 applied this would have been 0o600; the ACL's
        // group/other entries keep the wider bits instead.
        assert_ne!(got.mode, 0o600);
        assert_eq!(got.mode & 0o077, 0o064 & 0o077);
    }

    #[test]
    fn a_named_user_entry_forces_a_stored_access_acl() {
        let acl = default_acl_with_named_user();
        let got = inherit(Some(&acl), 0o666, 0o022, false);
        let access = got.access.expect("named user cannot be expressed in mode bits");
        let parsed = parse(&access).unwrap();
        assert!(parsed.iter().any(|e| e.tag == TAG_USER && e.id == 1234));
    }

    /// An ACL that is just the three mode triads carries nothing extra, so no
    /// access ACL should be stored -- matching the kernel, and keeping the
    /// common case free of a pointless xattr on every created file.
    #[test]
    fn an_equivalent_acl_stores_no_access_xattr() {
        let acl = serialize(&[
            entry(TAG_USER_OBJ, 6, u32::MAX),
            entry(TAG_GROUP_OBJ, 4, u32::MAX),
            entry(TAG_OTHER, 4, u32::MAX),
        ]);
        let got = inherit(Some(&acl), 0o666, 0o022, false);
        assert!(got.access.is_none());
        assert_eq!(got.mode & 0o777, 0o644);
    }

    #[test]
    fn only_directories_inherit_the_default_acl_onward() {
        let acl = default_acl_with_named_user();
        assert!(inherit(Some(&acl), 0o777, 0o022, true).default.is_some());
        assert!(inherit(Some(&acl), 0o666, 0o022, false).default.is_none());
    }

    /// The created mode can never exceed what the caller asked for; the ACL
    /// can only narrow it.
    #[test]
    fn inherited_mode_never_widens_beyond_the_requested_mode() {
        let acl = serialize(&[
            entry(TAG_USER_OBJ, 7, u32::MAX),
            entry(TAG_GROUP_OBJ, 7, u32::MAX),
            entry(TAG_MASK, 7, u32::MAX),
            entry(TAG_OTHER, 7, u32::MAX),
        ]);
        let got = inherit(Some(&acl), 0o644, 0, false);
        assert_eq!(got.mode & 0o777 & !0o644, 0, "mode {:o} widened", got.mode);
    }

    #[test]
    fn a_mask_less_acl_without_a_group_obj_is_rejected() {
        let acl = serialize(&[entry(TAG_USER_OBJ, 7, u32::MAX), entry(TAG_OTHER, 5, u32::MAX)]);
        let got = inherit(Some(&acl), 0o666, 0o022, false);
        // Falls back to umask rather than inventing permissions.
        assert_eq!(got.mode, 0o644);
        assert!(got.access.is_none());
    }
}
