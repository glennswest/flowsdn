//! Compile-time symbol coverage for spec 02 §11.8; no runtime capability claim.
#[allow(dead_code)]
fn bindings_present() {
    let _ = aya_ebpf::helpers::bpf_fib_lookup;
    let _ = aya_ebpf::helpers::bpf_redirect_neigh;
    let _ = aya_ebpf::helpers::bpf_redirect_peer;
    let _ = aya_ebpf::helpers::bpf_sk_assign;
    let _ = aya_ebpf::helpers::bpf_skc_lookup_tcp;
    let _ = aya_ebpf::helpers::bpf_sk_lookup_udp;
    let _ = aya_ebpf::helpers::bpf_sk_release;
    let _ = aya_ebpf::helpers::bpf_skb_set_tunnel_key;
    let _ = aya_ebpf::helpers::bpf_skb_get_tunnel_key;
    let _ = aya_ebpf::helpers::bpf_skb_set_tunnel_opt;
    let _ = aya_ebpf::helpers::bpf_skb_get_tunnel_opt;
    let _ = aya_ebpf::helpers::bpf_csum_diff;
    let _ = aya_ebpf::helpers::bpf_get_hash_recalc;
    let _ = aya_ebpf::helpers::bpf_skb_change_head;
    let _ = aya_ebpf::helpers::bpf_skb_change_type;
    let _ = aya_ebpf::helpers::bpf_skb_change_proto;
    let _ = aya_ebpf::helpers::bpf_skb_change_tail;
    let _ = aya_ebpf::helpers::bpf_clone_redirect;
    let _ = aya_ebpf::helpers::bpf_jiffies64;
    let _ = aya_ebpf::helpers::bpf_map_lookup_percpu_elem;
    let _ = aya_ebpf::helpers::bpf_set_retval;
    let _ = aya_ebpf::helpers::bpf_for_each_map_elem;
    let _ = aya_ebpf::helpers::bpf_loop;
}
