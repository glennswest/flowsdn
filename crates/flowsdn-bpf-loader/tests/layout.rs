use flowsdn_bpf_loader::layout::{LayoutError, ScratchLayout, TargetArchitecture as Arch};

#[test]
fn target_cache_lines_drive_exact_stride_and_storage() {
    for (arch, section, stride, size, last) in [
        (Arch::X86_64, 1, 64, 256, 192),
        (Arch::Aarch64, 1, 128, 512, 384),
        (Arch::X86_64, 64, 64, 256, 192),
        (Arch::Aarch64, 64, 128, 512, 384),
        (Arch::X86_64, 65, 128, 512, 384),
        (Arch::Aarch64, 129, 256, 1024, 768),
    ] {
        let layout = ScratchLayout::new(section, 4, arch).expect("valid layout");
        assert_eq!(
            (layout.stride(), layout.value_size(), layout.max_offset()),
            (stride, size, last)
        );
    }
}
#[test]
fn addressing_clamps_unexpected_cpu_without_wrapping() {
    let layout = ScratchLayout::new(65, 3, Arch::X86_64).expect("layout");
    assert_eq!(layout.offset_for_cpu(0), 0);
    assert_eq!(layout.offset_for_cpu(1), 128);
    for cpu in [2, 3, 1000, u32::MAX] {
        assert_eq!(layout.offset_for_cpu(cpu), 256);
    }
    let single = ScratchLayout::new(1, 1, Arch::Aarch64).expect("layout");
    assert_eq!(single.max_offset(), 0);
    assert_eq!(single.offset_for_cpu(u32::MAX), 0);
}
#[test]
fn empty_input_and_both_overflow_stages_fail_before_map_allocation() {
    for arch in [Arch::X86_64, Arch::Aarch64] {
        assert_eq!(
            ScratchLayout::new(0, 1, arch),
            Err(LayoutError::EmptySection)
        );
        assert_eq!(
            ScratchLayout::new(1, 0, arch),
            Err(LayoutError::NoPossibleCpus)
        );
        assert_eq!(
            ScratchLayout::new(u32::MAX, 1, arch),
            Err(LayoutError::ValueSizeOverflow)
        );
        assert_eq!(
            ScratchLayout::new(1, u32::MAX, arch),
            Err(LayoutError::ValueSizeOverflow)
        );
    }
    let layout = ScratchLayout::new(0xffff_ff80, 1, Arch::Aarch64).expect("largest aligned value");
    assert_eq!(layout.value_size(), 0xffff_ff80);
    assert_eq!(
        ScratchLayout::new(0xffff_ff80, 2, Arch::Aarch64),
        Err(LayoutError::ValueSizeOverflow)
    );
}
