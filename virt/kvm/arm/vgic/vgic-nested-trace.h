/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_VGIC_NESTED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VGIC_NESTED_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

TRACE_EVENT(vgic_restore_shadow_lr,
	TP_PROTO(struct kvm_vcpu *vcpu, int lr_idx, u64 lr, u64 orig_lr),
	TP_ARGS(vcpu, lr_idx, lr, orig_lr),

	TP_STRUCT__entry(
		__field(	int,	lr_idx			)
		__field(	u64,	lr			)
		__field(	u64,	orig_lr			)
	),

	TP_fast_assign(
		__entry->lr_idx		= lr_idx;
		__entry->lr		= lr;
		__entry->orig_lr	= orig_lr;
	),

	TP_printk("LR[%2d]: HW: %d P: %d: A: %d vINTID: %5llu pINTID: %5llu (%5llu)\n",
		   __entry->lr_idx,
		   !!(__entry->lr & ICH_LR_HW),
		   !!(__entry->lr & ICH_LR_PENDING_BIT),
		   !!(__entry->lr & ICH_LR_ACTIVE_BIT),
		   __entry->lr & ICH_LR_VIRTUAL_ID_MASK,
		   (__entry->lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT,
		   (__entry->orig_lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT)
);

TRACE_EVENT(vgic_save_shadow_lr,
	TP_PROTO(struct kvm_vcpu *vcpu, int lr_idx, u64 lr, u64 orig_lr),
	TP_ARGS(vcpu, lr_idx, lr, orig_lr),

	TP_STRUCT__entry(
		__field(	int,	lr_idx			)
		__field(	u64,	lr			)
		__field(	u64,	orig_lr			)
	),

	TP_fast_assign(
		__entry->lr_idx		= lr_idx;
		__entry->lr		= lr;
		__entry->orig_lr	= orig_lr;
	),

	TP_printk("LR[%2d]: HW: %d P: %d: A: %d vINTID: %5llu pINTID: %5llu (%5llu)\n",
		   __entry->lr_idx,
		   !!(__entry->lr & ICH_LR_HW),
		   !!(__entry->lr & ICH_LR_PENDING_BIT),
		   !!(__entry->lr & ICH_LR_ACTIVE_BIT),
		   __entry->lr & ICH_LR_VIRTUAL_ID_MASK,
		   (__entry->lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT,
		   (__entry->orig_lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT)
);

TRACE_EVENT(vgic_nested_hw_emulate,
	TP_PROTO(int lr, u64 lr_val, u32 l1_intid),
	TP_ARGS(lr, lr_val, l1_intid),

	TP_STRUCT__entry(
		__field(	int,	lr		)
		__field(	u64,	lr_val		)
		__field(	u32,	l1_intid	)
	),

	TP_fast_assign(
		__entry->lr		= lr;
		__entry->lr_val		= lr_val;
		__entry->l1_intid	= l1_intid;
	),

	TP_printk("lr: %d LR %llx L1 INTID: %u\n",
		  __entry->lr, __entry->lr_val, __entry->l1_intid)
);

#endif /* _TRACE_VGIC_NESTED_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../virt/kvm/arm/vgic
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE vgic-nested-trace

/* This part must be outside protection */
#include <trace/define_trace.h>
