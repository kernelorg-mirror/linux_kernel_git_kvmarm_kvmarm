/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kvm_host.h>

#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nested.h>

/* Must be called with kvm->lock held */
struct kvm_s2_mmu *lookup_s2_mmu(struct kvm *kvm, u64 vttbr, u64 hcr)
{
	bool nested_stage2_enabled = hcr & HCR_VM;
	int i;

	/* Don't consider the CnP bit for the vttbr match */
	vttbr = vttbr & ~1UL;

	/* Search a mmu in the list using the virtual VMID as a key */
	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (mmu->usage_count < 0)
			continue;

		if (nested_stage2_enabled &&
		    mmu->nested_stage2_enabled &&
		    vttbr == (mmu->vttbr & ~1UL))
			return mmu;

		if (!nested_stage2_enabled &&
		    !mmu->nested_stage2_enabled &&
		    get_vmid(vttbr) == get_vmid(mmu->vttbr))
			return mmu;
	}
	return NULL;
}

static struct kvm_s2_mmu *get_s2_mmu_nested(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	u64 vttbr = vcpu_read_sys_reg(vcpu, VTTBR_EL2);
	u64 hcr= vcpu_read_sys_reg(vcpu, HCR_EL2);
	struct kvm_s2_mmu *s2_mmu;
	int i;

	s2_mmu = lookup_s2_mmu(kvm, vttbr, hcr);
	if (s2_mmu)
		goto out;

	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		s2_mmu = &kvm->arch.nested_mmus[i];

		if (s2_mmu->usage_count <= 0)
			break;
	}
	BUG_ON(s2_mmu->usage_count > 0); /* We have struct MMUs to spare */

	if (s2_mmu->usage_count == 0) {
		/* Clear the old state */
		kvm_unmap_stage2_range(kvm, s2_mmu, 0, KVM_PHYS_SIZE);
		if (s2_mmu->vmid.vmid_gen)
			kvm_call_hyp(__kvm_tlb_flush_vmid, kvm_get_vttbr(s2_mmu));
	} else {
		s2_mmu->usage_count = 0;
	}

	/*
	 * The virtual VMID (modulo CnP) will be used as a key when matching
	 * an existing kvm_s2_mmu.
	 */
	s2_mmu->vttbr = vttbr & ~1UL;
	s2_mmu->nested_stage2_enabled = hcr & HCR_VM;

out:
	s2_mmu->usage_count++;
	return s2_mmu;
}

void kvm_vcpu_load_hw_mmu(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->kvm->mmu_lock);
	if (is_hyp_ctxt(vcpu))
		vcpu->arch.hw_mmu = &vcpu->kvm->arch.mmu;
	else
		vcpu->arch.hw_mmu = get_s2_mmu_nested(vcpu);
	spin_unlock(&vcpu->kvm->mmu_lock);
}

void kvm_vcpu_put_hw_mmu(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->kvm->mmu_lock);
	if (vcpu->arch.hw_mmu != &vcpu->kvm->arch.mmu) {
		vcpu->arch.hw_mmu->usage_count--;
		vcpu->arch.hw_mmu = NULL;
	}
	spin_unlock(&vcpu->kvm->mmu_lock);
}
