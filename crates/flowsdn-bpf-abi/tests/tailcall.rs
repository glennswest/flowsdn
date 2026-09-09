use flowsdn_bpf_abi::tailcall::{CALL_SIZE, SLOTS, TailSlot};

#[test]
fn supported_slots_are_unique_and_reserved_holes_stay_invalid() {
    assert_eq!(CALL_SIZE, 50);
    assert_eq!(SLOTS.len(), 48);
    for number in 0..=255 {
        let expected = (1..50).contains(&number) && number != 3;
        assert_eq!(TailSlot::from_number(number).is_ok(), expected);
        assert_eq!(SLOTS.iter().filter(|slot| slot.number() == number).count(), usize::from(expected));
    }
    assert!(TailSlot::from_number(u32::MAX).is_err());
}
#[test]
fn observable_slot_numbers_match_frozen_contract() {
    for (slot, number) in [
        (TailSlot::DropNotify, 1), (TailSlot::ErrorNotify, 2),
        (TailSlot::Ipv4FromLxc, 7), (TailSlot::Ipv6FromLxc, 10),
        (TailSlot::Ipv4CtIngressPolicyOnly, 29), (TailSlot::Ipv4CtEgress, 30),
        (TailSlot::Ipv6CtEgress, 33), (TailSlot::Srv6Encap, 34),
        (TailSlot::Ipv4InterClusterRevsnat, 40), (TailSlot::MulticastEpDelivery, 47),
        (TailSlot::Ipv4PolicyDenied, 48), (TailSlot::Ipv6PolicyDenied, 49),
    ] {
        assert_eq!(slot.number(), number);
        assert_eq!(TailSlot::try_from(number), Ok(slot));
    }
}
