//! Checked auxiliary scratch layout from map ABI/loader specification §5.4.
//! This plans patch values only; it does not allocate or initialize a map.
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetArchitecture {
    X86_64,
    Aarch64,
}
impl TargetArchitecture {
    pub const fn cache_line_bytes(self) -> u32 {
        match self {
            Self::X86_64 => 64,
            Self::Aarch64 => 128,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    EmptySection,
    NoPossibleCpus,
    ValueSizeOverflow,
}
impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptySection => "scratch section must not be empty",
            Self::NoPossibleCpus => "at least one possible CPU is required",
            Self::ValueSizeOverflow => "scratch map value exceeds the u32 map ABI",
        })
    }
}
impl core::error::Error for LayoutError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScratchLayout {
    stride: u32,
    value_size: u32,
    max_offset: u32,
}
impl ScratchLayout {
    /// Plan an existing nonempty scratch section using possible CPUs (including
    /// offline CPUs), not online CPUs. The owner must create zeroed storage.
    pub fn new(
        section_size: u32,
        possible_cpus: u32,
        target: TargetArchitecture,
    ) -> Result<Self, LayoutError> {
        if section_size == 0 {
            return Err(LayoutError::EmptySection);
        }
        if possible_cpus == 0 {
            return Err(LayoutError::NoPossibleCpus);
        }
        let line = target.cache_line_bytes();
        let remainder = section_size % line;
        let padding = if remainder == 0 {
            0
        } else {
            line.checked_sub(remainder)
                .ok_or(LayoutError::ValueSizeOverflow)?
        };
        let stride = section_size
            .checked_add(padding)
            .ok_or(LayoutError::ValueSizeOverflow)?;
        let value_size = stride
            .checked_mul(possible_cpus)
            .ok_or(LayoutError::ValueSizeOverflow)?;
        let max_offset = value_size
            .checked_sub(stride)
            .ok_or(LayoutError::ValueSizeOverflow)?;
        Ok(Self {
            stride,
            value_size,
            max_offset,
        })
    }
    pub const fn stride(self) -> u32 {
        self.stride
    }
    pub const fn value_size(self) -> u32 {
        self.value_size
    }
    pub const fn max_offset(self) -> u32 {
        self.max_offset
    }
    /// Match the specified clamped AUX addressing even for an unexpected CPU.
    pub fn offset_for_cpu(self, cpu: u32) -> u32 {
        self.stride.saturating_mul(cpu).min(self.max_offset)
    }
}
