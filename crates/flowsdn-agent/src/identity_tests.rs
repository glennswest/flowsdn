use super::*;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}
fn filter() -> LabelFilter {
    LabelFilter::identity(&[]).expect("default filter")
}
fn web() -> Labels {
    pod_labels(
        "web",
        &map(&[("app", "web"), ("pod-template-hash", "abc")]),
        Some(&map(&[("kubernetes.io/metadata.name", "web")])),
        "default",
        "default",
        &filter(),
    )
}
fn object(id: u32, labels: &Labels, created: &str) -> Object {
    let security = labels
        .iter()
        .map(|l| (format!("{}:{}", l.source(), l.key()), l.value().to_owned()))
        .collect();
    Object::new(id, &security, created, false, "1")
}
fn desired(sets: &[Labels]) -> BTreeMap<String, Labels> {
    sets.iter()
        .map(|l| (l.canonical_key(), l.clone()))
        .collect()
}

#[test]
fn pod_labels_follow_the_label_model_with_flowsdn_keys() {
    let labels = pod_labels(
        "web",
        &map(&[
            ("app", "web"),
            ("pod-template-hash", "abc"),
            ("io.flowsdn.k8s.policy.cluster", "spoofed"),
            ("io.flowsdn.k8s.policy.serviceaccount", "admin"),
        ]),
        Some(&map(&[
            ("kubernetes.io/metadata.name", "web"),
            ("team", "a"),
        ])),
        "builder",
        "default",
        &filter(),
    );
    assert_eq!(
        label_strings(&labels),
        [
            "k8s:app=web",
            "k8s:io.flowsdn.k8s.namespace.labels.kubernetes.io/metadata.name=web",
            "k8s:io.flowsdn.k8s.namespace.labels.team=a",
            "k8s:io.flowsdn.k8s.policy.cluster=default",
            "k8s:io.flowsdn.k8s.policy.serviceaccount=builder",
            "k8s:io.kubernetes.pod.namespace=web",
        ]
    );
    // No service account: the key is absent, not empty.
    let labels = pod_labels("web", &BTreeMap::new(), None, "", "c1", &filter());
    assert!(labels.get(SERVICE_ACCOUNT).is_none());
    assert_eq!(
        labels.canonical_key(),
        "k8s:io.flowsdn.k8s.policy.cluster=c1;k8s:io.kubernetes.pod.namespace=web;"
    );
}

#[test]
fn cluster_dns_pods_get_the_well_known_identities() {
    let dns = |account: &str, extra: &[(&str, &str)], ns: Option<&BTreeMap<String, String>>| {
        let mut labels = map(&[("k8s-app", "kube-dns"), ("pod-template-hash", "x")]);
        labels.extend(map(extra));
        pod_labels("kube-system", &labels, ns, account, "default", &filter())
    };
    let metadata = map(&[("kubernetes.io/metadata.name", "kube-system")]);
    let eks = [("eks.amazonaws.com/component", "coredns")];
    assert_eq!(
        well_known(&dns("kube-dns", &[], None), "default"),
        Some(102)
    );
    assert_eq!(well_known(&dns("coredns", &[], None), "default"), Some(104));
    assert_eq!(
        well_known(&dns("coredns", &eks, None), "default"),
        Some(106)
    );
    assert_eq!(
        well_known(&dns("kube-dns", &[], Some(&metadata)), "default"),
        Some(110)
    );
    assert_eq!(
        well_known(&dns("coredns", &[], Some(&metadata)), "default"),
        Some(112)
    );
    // Another cluster name, an extra label or namespace label: not well-known.
    assert_eq!(well_known(&dns("coredns", &[], None), "other"), None);
    assert_eq!(
        well_known(&dns("coredns", &[("version", "1")], None), "default"),
        None
    );
    let more = map(&[("kubernetes.io/metadata.name", "kube-system"), ("x", "y")]);
    assert_eq!(
        well_known(&dns("coredns", &[], Some(&more)), "default"),
        None
    );
    assert_eq!(well_known(&web(), "default"), None);
    let mut allocator = Allocator::default();
    let set = dns("coredns", &[], None);
    assert!(
        allocator
            .reconcile(&desired(&[set.clone()]), &[], "default", 0)
            .is_empty()
    );
    assert_eq!(allocator.get(&set.canonical_key()), Some(104));
}

#[test]
fn a_new_label_set_creates_a_free_number_and_holds_it_once_created() {
    let mut allocator = Allocator::default();
    let taken = object(
        256,
        &pod_labels("a", &BTreeMap::new(), None, "", "default", &filter()),
        "t",
    );
    let want = desired(&[web()]);
    let actions = allocator.reconcile(&want, &[taken.clone()], "default", 0);
    assert_eq!(
        actions,
        [Action::Create {
            id: 257,
            labels: web()
        }]
    );
    let key = web().canonical_key();
    assert_eq!(
        allocator.get(&key),
        None,
        "not before the create is answered"
    );
    // Unanswered: no second create for the same set.
    assert!(
        allocator
            .reconcile(&want, &[taken.clone()], "default", 0)
            .is_empty()
    );
    allocator.created(&key, 257, Outcome::Done);
    assert_eq!(allocator.get(&key), Some(257));
    assert_eq!(allocator.waiting(&want), 0);
    // Created but not listed yet: not taken for a deletion, no recreate.
    assert!(
        allocator
            .reconcile(&want, &[taken.clone()], "default", 0)
            .is_empty()
    );
    let listed = object(257, &web(), "t");
    assert!(
        allocator
            .reconcile(&want, &[taken.clone(), listed], "default", 0)
            .is_empty()
    );
    // Listed, then gone: recreated.
    assert_eq!(
        allocator
            .reconcile(&want, &[taken], "default", 0)
            .first()
            .map(Action::id),
        Some(257)
    );

    let action = actions.first().expect("action");
    let body = action.body();
    assert_eq!(body.pointer("/apiVersion"), Some(&json!(API_VERSION)));
    assert_eq!(body.pointer("/kind"), Some(&json!(KIND)));
    assert_eq!(body.pointer("/metadata/name"), Some(&json!("257")));
    assert_eq!(
        body.pointer("/metadata/labels/io.kubernetes.pod.namespace"),
        Some(&json!("web"))
    );
    assert_eq!(
        body.pointer("/security-labels/k8s:app"),
        Some(&json!("web"))
    );
    assert_eq!(body.pointer("/metadata/resourceVersion"), None);
    assert_eq!(action.path("/c"), "/c");
}

#[test]
fn a_refused_create_leases_again_and_a_peer_object_is_reused() {
    let mut allocator = Allocator::default();
    let want = desired(&[web()]);
    let key = web().canonical_key();
    let first = allocator.reconcile(&want, &[], "default", 5);
    assert_eq!(first.first().map(Action::id), Some(261));
    allocator.created(&key, 261, Outcome::Conflict);
    assert_eq!(allocator.get(&key), None);
    // Another node created the same labels meanwhile: reuse, no create.
    let peer = object(4000, &web(), "2026-10-09T10:00:00Z");
    assert!(allocator.reconcile(&want, &[peer], "default", 5).is_empty());
    assert_eq!(allocator.get(&key), Some(4000));
}

#[test]
fn lookups_converge_on_the_oldest_object_and_keep_a_held_duplicate() {
    let older = object(900, &web(), "2026-10-09T09:00:00Z");
    let newer = object(300, &web(), "2026-10-09T10:00:00Z");
    let tie = object(299, &web(), "2026-10-09T10:00:00Z");
    let objects = [newer.clone(), older.clone(), tie];
    let mut allocator = Allocator::default();
    let want = desired(&[web()]);
    assert!(
        allocator
            .reconcile(&want, &objects, "default", 0)
            .is_empty()
    );
    assert_eq!(allocator.get(&web().canonical_key()), Some(900));
    // Ties go to the lower number.
    let objects = [newer, object(299, &web(), "2026-10-09T10:00:00Z")];
    assert_eq!(oldest(&objects).values().next().map(|o| o.id), Some(299));
    // A node holding a newer duplicate keeps it (no renumbering, step 6).
    let mut holder = Allocator::default();
    holder.reconcile(&want, &[object(300, &web(), "b")], "default", 0);
    holder.reconcile(&want, &[older, object(300, &web(), "b")], "default", 0);
    assert_eq!(holder.get(&web().canonical_key()), Some(300));
}

#[test]
fn heartbeat_is_removed_and_a_deleted_held_identity_is_recreated() {
    let mut allocator = Allocator::default();
    let want = desired(&[web()]);
    let mut marked = object(700, &web(), "t");
    marked.heartbeat = true;
    marked.resource_version = "42".into();
    let actions = allocator.reconcile(&want, &[marked], "default", 0);
    assert_eq!(
        actions,
        [Action::Acquire {
            id: 700,
            labels: web(),
            resource_version: "42".into()
        }]
    );
    let action = actions.first().expect("action");
    let body = action.body();
    assert_eq!(
        body.pointer("/metadata/resourceVersion"),
        Some(&json!("42"))
    );
    assert_eq!(body.pointer("/metadata/annotations"), None);
    assert_eq!(action.path("/c"), "/c/700");
    // The object disappears (GC on a partitioned node): recreate the number.
    assert_eq!(
        allocator.reconcile(&want, &[], "default", 0),
        [Action::Create {
            id: 700,
            labels: web()
        }]
    );
    // A failed recreate keeps the hold; the next pass tries again.
    allocator.created(&web().canonical_key(), 700, Outcome::Failed);
    assert_eq!(allocator.get(&web().canonical_key()), Some(700));
    // The number came back with other labels: look up / lease afresh.
    let other = pod_labels("x", &BTreeMap::new(), None, "", "default", &filter());
    let actions = allocator.reconcile(&want, &[object(700, &other, "t")], "default", 0);
    assert_eq!(actions.first().map(Action::id), Some(256));
}

#[test]
fn released_sets_are_dropped_and_their_numbers_not_reused_while_objects_exist() {
    let mut allocator = Allocator::default();
    let want = desired(&[web()]);
    allocator.reconcile(&want, &[object(256, &web(), "t")], "default", 0);
    assert!(
        allocator
            .reconcile(&BTreeMap::new(), &[], "default", 0)
            .is_empty()
    );
    assert_eq!(allocator.get(&web().canonical_key()), None);
    let used: BTreeSet<u32> = (MIN_ID..=MAX_ID).collect();
    assert_eq!(free(&used, 7), None);
    let used: BTreeSet<u32> = [MAX_ID].into_iter().collect();
    // 65 279 is the offset of MAX_ID; the search wraps to MIN_ID.
    assert_eq!(free(&used, 65_279), Some(MIN_ID));
    // u32::MAX % 65 280 = 255.
    assert_eq!(free(&BTreeSet::new(), u32::MAX), Some(511));
}

#[test]
fn objects_with_unusable_labels_only_take_their_number() {
    let bad = Object::new(256, &map(&[("k8s:", "x")]), "t", false, "1");
    assert_eq!(bad.labels, None);
    let mut allocator = Allocator::default();
    let actions = allocator.reconcile(&desired(&[web()]), &[bad], "default", 0);
    assert_eq!(actions.first().map(Action::id), Some(257));
}
