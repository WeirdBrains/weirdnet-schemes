use libp2p_identity::Keypair;
use weirdnet_schemes::signed::{encode_key, key_id};
use weirdnet_schemes::*;

const NOW: u64 = 1_800_000_000;
const LATER: u64 = NOW + 86400 * 365;

fn prefix(p: &str, k: &Keypair, seq: u64) -> PrefixRecord {
    PrefixRecord::new(p, &k.public(), seq, LATER)
}

fn scheme(s: &str, p: &str, app: &str, k: &Keypair, seq: u64) -> SchemeRecord {
    SchemeRecord {
        format: 1,
        scheme: s.into(),
        prefix: p.into(),
        app_id: app.into(),
        publisher: encode_key(&k.public()),
        display_name: "App".into(),
        capabilities: vec!["browse".into(), "join".into(), "answer".into()],
        install: vec![
            InstallHint::SaltyGull(app.into()),
            InstallHint::FDroid(app.into()),
            InstallHint::Https("https://weirdbrains.com/morph".into()),
        ],
        seq,
        expires: LATER,
        withdrawn: false,
    }
}

fn first_party(root: &Keypair, morph: &Keypair, seq: u64) -> Signed {
    let p = prefix("weirdnet-morph", morph, 1).sign(morph).unwrap().sign(Role::Root, root).unwrap();
    let s = scheme("weirdnet-morph", "weirdnet-morph", "org.weirdbrains.morph", morph, 1).sign(morph).unwrap().sign(Role::Root, root).unwrap();
    CanonicalList { format: 1, seq, issued: NOW, expires: LATER, prefixes: vec![p], schemes: vec![s] }.sign(root).unwrap()
}

fn registry(root: &Keypair) -> Registry {
    Registry::new(TrustAnchors::from_keys(vec![root.public()]))
}

#[test]
fn the_canonical_list_resolves_first_party_schemes() {
    let (root, morph) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut r = registry(&root);
    r.load_canonical(&first_party(&root, &morph, 1), NOW).unwrap();
    let Resolution::App { record, installed, because } = r.resolve("weirdnet-morph", NOW) else { panic!() };
    assert_eq!((record.app_id.as_str(), installed, because), ("org.weirdbrains.morph", false, Because::Canonical));
    assert_eq!(record.hints_for(Platform::Desktop).len(), 2);
    assert_eq!(record.hints_for(Platform::AndroidFDroid).len(), 2);
    assert_eq!(record.hints_for(Platform::Ios), vec![&InstallHint::Https("https://weirdbrains.com/morph".into())]);
    r.set_installed("org.weirdbrains.morph", &key_id(&morph.public()));
    assert!(matches!(r.resolve("WEIRDNET-MORPH", NOW), Resolution::App { installed: true, .. }));
    assert_eq!(r.resolve("weirdnet", NOW), Resolution::Internal);
    assert_eq!(r.resolve("weirdnet-muninn", NOW), Resolution::Unknown);

    // Stale, untrusted, expired, and reserved records without the root signature.
    assert!(matches!(r.load_canonical(&first_party(&root, &morph, 1), NOW), Err(Error::Stale { .. })));
    let other = Keypair::generate_ed25519();
    assert!(matches!(r.load_canonical(&first_party(&other, &morph, 9), NOW), Err(Error::Signature(_))));
    assert!(matches!(r.load_canonical(&first_party(&root, &morph, 2), LATER + 1), Err(Error::Expired)));
    let p = prefix("weirdnet-morph", &morph, 1).sign(&morph).unwrap();
    let list = CanonicalList { format: 1, seq: 5, issued: NOW, expires: LATER, prefixes: vec![p], schemes: vec![] }.sign(&root).unwrap();
    assert!(matches!(r.load_canonical(&list, NOW), Err(Error::Signature(_))));
    assert_eq!(r.canonical_seq(), Some(1));
}

#[test]
fn reserved_prefixes_come_only_from_the_canonical_list() {
    let (root, morph, mallory) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut r = registry(&root);
    r.load_canonical(&first_party(&root, &morph, 1), NOW).unwrap();
    for p in ["weirdnet-morph", "weirdnet-evil", "weirdnetx"] {
        let s = prefix(p, &mallory, 9).sign(&mallory).unwrap();
        assert!(matches!(r.add(&s, Source::Relay, NOW), Err(Error::Reserved(_))), "{p}");
    }
    let s = scheme("weirdnet-morph", "weirdnet-morph", "evil.app", &mallory, 9).sign(&mallory).unwrap();
    assert!(matches!(r.add(&s, Source::Relay, NOW), Err(Error::Reserved(_))));
    // Even root-signed, they're accepted only inside the list.
    let s = prefix("weirdnet-new", &morph, 1).sign(&morph).unwrap().sign(Role::Root, &root).unwrap();
    assert!(matches!(r.add(&s, Source::Relay, NOW), Err(Error::Reserved(_))));
    assert!(matches!(r.resolve("weirdnet-morph", NOW), Resolution::App { because: Because::Canonical, .. }));
    // Standard schemes can't be prefixes or schemes at all.
    assert!(prefix("https", &mallory, 1).sign(&mallory).is_err());
}

#[test]
fn strangers_are_never_picked_silently() {
    let (root, acme, other) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut r = registry(&root);
    // A scheme without its prefix registration is refused.
    let s = scheme("acme-notes", "acme", "com.acme.notes", &acme, 1).sign(&acme).unwrap();
    assert!(matches!(r.add(&s, Source::Relay, NOW), Err(Error::NotOwner { .. })));
    assert_eq!(r.add(&prefix("acme", &acme, 1).sign(&acme).unwrap(), Source::Relay, NOW).unwrap(), Added::New);
    assert_eq!(r.add(&s, Source::Relay, NOW).unwrap(), Added::New);
    assert!(matches!(r.resolve("acme-notes", NOW), Resolution::Choose(v) if v.len() == 1));

    // A second publisher claims the same prefix and scheme: still a choice.
    r.add(&prefix("acme", &other, 1).sign(&other).unwrap(), Source::Relay, NOW).unwrap();
    r.add(&scheme("acme-notes", "acme", "com.other.notes", &other, 1).sign(&other).unwrap(), Source::Relay, NOW).unwrap();
    assert!(matches!(r.resolve("acme-notes", NOW), Resolution::Choose(v) if v.len() == 2));

    // The installed app wins over strangers; the user's pin wins over that.
    r.set_installed("com.acme.notes", &key_id(&acme.public()));
    assert!(
        matches!(r.resolve("acme-notes", NOW), Resolution::App { because: Because::Installed, ref record, .. } if record.app_id == "com.acme.notes")
    );
    r.pin("acme-notes", &key_id(&other.public()));
    assert!(
        matches!(r.resolve("acme-notes", NOW), Resolution::App { because: Because::Pinned, installed: false, ref record } if record.app_id == "com.other.notes")
    );
    // A pin to a publisher with no live record resolves to nothing rather than to someone else.
    r.pin("acme-notes", "0".repeat(32).as_str());
    assert_eq!(r.resolve("acme-notes", NOW), Resolution::Unknown);
    r.unpin("acme-notes");
    // Installed app id but another publisher's key: not trusted.
    r.set_installed("com.other.notes", &key_id(&acme.public()));
    assert!(
        matches!(r.resolve("acme-notes", NOW), Resolution::App { because: Because::Installed, ref record, .. } if record.app_id == "com.acme.notes")
    );
}

#[test]
fn seq_withdrawal_expiry_and_transfer() {
    let (root, acme, buyer) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut r = registry(&root);
    r.add(&prefix("acme", &acme, 2).sign(&acme).unwrap(), Source::Relay, NOW).unwrap();
    assert!(matches!(r.add(&prefix("acme", &acme, 2).sign(&acme).unwrap(), Source::Relay, NOW), Err(Error::Stale { got: 2, have: 2 })));
    r.add(&scheme("acme-notes", "acme", "com.acme.notes", &acme, 1).sign(&acme).unwrap(), Source::Relay, NOW).unwrap();
    r.set_installed("com.acme.notes", &key_id(&acme.public()));
    assert!(matches!(r.resolve("acme-notes", NOW), Resolution::App { .. }));
    assert_eq!(r.resolve("acme-notes", LATER + 1), Resolution::Unknown, "expired");
    let mut w = scheme("acme-notes", "acme", "com.acme.notes", &acme, 2);
    w.withdrawn = true;
    assert_eq!(r.add(&w.sign(&acme).unwrap(), Source::Relay, NOW).unwrap(), Added::Withdrawn);
    assert_eq!(r.resolve("acme-notes", NOW), Resolution::Unknown);
    assert!(matches!(
        r.add(&scheme("acme-notes", "acme", "com.acme.notes", &acme, 2).sign(&acme).unwrap(), Source::Relay, NOW),
        Err(Error::Stale { .. })
    ));
    r.add(&scheme("acme-notes", "acme", "com.acme.notes", &acme, 3).sign(&acme).unwrap(), Source::Relay, NOW).unwrap();

    // A transfer signed by the previous holder removes its claim and schemes.
    let t = prefix("acme", &buyer, 1).sign(&buyer).unwrap().sign(Role::Transfer, &acme).unwrap();
    r.add(&t, Source::Relay, NOW).unwrap();
    assert_eq!(r.resolve("acme-notes", NOW), Resolution::Unknown);
    assert!(matches!(
        r.add(&scheme("acme-notes", "acme", "com.acme.notes", &acme, 4).sign(&acme).unwrap(), Source::Relay, NOW),
        Err(Error::NotOwner { .. })
    ));
    r.add(&scheme("acme-notes", "acme", "com.buyer.notes", &buyer, 1).sign(&buyer).unwrap(), Source::Relay, NOW).unwrap();
    assert!(matches!(r.resolve("acme-notes", NOW), Resolution::Choose(v) if v[0].app_id == "com.buyer.notes"));
    // A transfer "signed" by someone who never held it does nothing to the holder.
    let mallory = Keypair::generate_ed25519();
    r.add(&prefix("acme", &mallory, 1).sign(&mallory).unwrap().sign(Role::Transfer, &mallory).unwrap(), Source::Relay, NOW).unwrap();
    r.add(&scheme("acme-notes", "acme", "com.buyer.notes", &buyer, 2).sign(&buyer).unwrap(), Source::Relay, NOW).unwrap();
}

#[test]
fn root_rotation_and_the_saved_cache() {
    let (root, next, morph) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut r = registry(&root);
    r.load_canonical(&first_party(&root, &morph, 1), NOW).unwrap();
    // Only both signatures rotate.
    let half = Signed::new("root-rotation", &RootRotation { format: 1, old: encode_key(&root.public()), new: encode_key(&next.public()), at: NOW })
        .sign(Role::Root, &root)
        .unwrap();
    assert!(r.anchors_mut().rotate(&half).is_err());
    r.anchors_mut().rotate(&RootRotation::sign(&root, &next, NOW).unwrap()).unwrap();
    assert!(matches!(r.load_canonical(&first_party(&root, &morph, 2), NOW), Err(Error::Signature(_))));
    r.load_canonical(&first_party(&next, &morph, 2), NOW).unwrap();
    // A rotation from an untrusted key is refused.
    let x = Keypair::generate_ed25519();
    assert!(r.anchors_mut().rotate(&RootRotation::sign(&x, &Keypair::generate_ed25519(), NOW).unwrap()).is_err());

    let saved = r.save();
    let back = Registry::restore(&saved, TrustAnchors::from_keys(vec![next.public()])).unwrap();
    assert_eq!(back.resolve("weirdnet-morph", NOW), r.resolve("weirdnet-morph", NOW));
    assert_eq!(back.records().len(), 2);
    // Records pass on: another device takes the relay copies (the first-party ones are
    // refused outside the list).
    let mut fresh = registry(&next);
    for s in back.records() {
        assert!(fresh.add(&s, Source::Relay, NOW).is_err());
    }
}
