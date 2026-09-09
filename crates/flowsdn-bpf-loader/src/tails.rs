//! Typed tail-program inventory checks from loader specification §5.3.
//! ELF parsing, reachability pruning and program-array insertion are separate.
use core::fmt;
use flowsdn_bpf_abi::tailcall::TailSlot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailError {
    DuplicateDeclaration(TailSlot),
    DuplicateProgram(TailSlot),
    UndeclaredProgram(TailSlot),
    MissingPrograms { slots: u64 },
}
impl fmt::Display for TailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateDeclaration(slot) => {
                write!(f, "tail slot {} is declared twice", slot.number())
            }
            Self::DuplicateProgram(slot) => {
                write!(f, "multiple programs claim tail slot {}", slot.number())
            }
            Self::UndeclaredProgram(slot) => {
                write!(f, "program claims undeclared tail slot {}", slot.number())
            }
            Self::MissingPrograms { slots } => write!(
                f,
                "declared tail programs are missing (slot mask {slots:#x})"
            ),
        }
    }
}
impl core::error::Error for TailError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TailInventory {
    slots: u64,
}
impl TailInventory {
    /// Each object's declared slots must have exactly one supplied program.
    /// Global endpoint-policy programs do not belong in these lists.
    pub fn validate(declared: &[TailSlot], programs: &[TailSlot]) -> Result<Self, TailError> {
        let mut wanted = 0_u64;
        for &slot in declared {
            let bit = 1_u64 << slot.number();
            if wanted & bit != 0 {
                return Err(TailError::DuplicateDeclaration(slot));
            }
            wanted |= bit;
        }
        let mut found = 0_u64;
        for &slot in programs {
            let bit = 1_u64 << slot.number();
            if wanted & bit == 0 {
                return Err(TailError::UndeclaredProgram(slot));
            }
            if found & bit != 0 {
                return Err(TailError::DuplicateProgram(slot));
            }
            found |= bit;
        }
        let missing = wanted & !found;
        if missing != 0 {
            return Err(TailError::MissingPrograms { slots: missing });
        }
        Ok(Self { slots: found })
    }
    pub const fn contains(self, slot: TailSlot) -> bool {
        self.slots & (1_u64 << slot.number()) != 0
    }
    pub const fn len(self) -> u32 {
        self.slots.count_ones()
    }
    pub const fn is_empty(self) -> bool {
        self.slots == 0
    }
}
