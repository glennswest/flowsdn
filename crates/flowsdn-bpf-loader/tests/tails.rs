use flowsdn_bpf_abi::tailcall::{SLOTS, TailSlot as Slot};
use flowsdn_bpf_loader::tails::{TailError, TailInventory};

#[test]
fn complete_inventory_accepts_any_program_order_and_empty_objects() {
    let mut reversed = SLOTS.to_vec();
    reversed.reverse();
    let inventory = TailInventory::validate(SLOTS, &reversed).expect("all declared tails");
    assert_eq!(inventory.len(), 48);
    assert!(!inventory.is_empty());
    for &slot in SLOTS { assert!(inventory.contains(slot)); }
    assert!(TailInventory::validate(&[], &[]).expect("no tails").is_empty());
}
#[test]
fn duplicate_declarations_and_claims_fail_independently() {
    assert_eq!(TailInventory::validate(&[Slot::DropNotify, Slot::DropNotify], &[Slot::DropNotify]), Err(TailError::DuplicateDeclaration(Slot::DropNotify)));
    assert_eq!(TailInventory::validate(&[Slot::DropNotify], &[Slot::DropNotify, Slot::DropNotify]), Err(TailError::DuplicateProgram(Slot::DropNotify)));
}
#[test]
fn undeclared_programs_and_all_missing_slots_are_reported() {
    assert_eq!(TailInventory::validate(&[Slot::DropNotify], &[Slot::ErrorNotify]), Err(TailError::UndeclaredProgram(Slot::ErrorNotify)));
    assert_eq!(TailInventory::validate(&[Slot::DropNotify, Slot::Ipv6PolicyDenied], &[]), Err(TailError::MissingPrograms { slots: 0x0002_0000_0000_0002 }));
    let partial = TailInventory::validate(&[Slot::DropNotify], &[Slot::DropNotify]).expect("one tail");
    assert!(!partial.contains(Slot::Ipv6PolicyDenied));
}
