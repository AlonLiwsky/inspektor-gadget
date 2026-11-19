IG ?= ig
IMAGE ?= enforce-exec-owner:experimental
ABI3_DEVELOPMENT ?= 0
SHARED_DEVELOPMENT ?= 0
SHARED_RECOVERY_DEVELOPMENT ?= 0
export SHARED_TASKS SHARED_SCRATCH SHARED_ACCEPTED_UIDS SHARED_TASK_QUOTA SHARED_SCRATCH_QUOTA SHARED_INODE_FACTS SHARED_INODE_QUOTA
export SHARED_IMAGES SHARED_IMAGE_QUOTA
export SHARED_DEVELOPMENT SHARED_RECOVERY_DEVELOPMENT SHARED_BINDINGS SHARED_SLOTS_256 SHARED_SLOTS_1024 SHARED_SLOTS_4096 SHARED_SLOTS_16384
ifeq ($(SHARED_RECOVERY_DEVELOPMENT),1)
ifneq ($(SHARED_DEVELOPMENT),1)
$(error SHARED_RECOVERY_DEVELOPMENT requires SHARED_DEVELOPMENT=1)
endif
ifneq ($(ABI3_DEVELOPMENT),1)
$(error SHARED_RECOVERY_DEVELOPMENT requires ABI3_DEVELOPMENT=1)
endif
ifeq ($(filter %:abi3-recovery-development,$(IMAGE)),)
$(error SHARED_RECOVERY_DEVELOPMENT requires explicit IMAGE ending :abi3-recovery-development)
endif
else ifneq ($(SHARED_RECOVERY_DEVELOPMENT),0)
$(error SHARED_RECOVERY_DEVELOPMENT must be 0 or 1)
else ifneq ($(filter %:abi3-recovery-development,$(IMAGE)),)
$(error recovery IMAGE requires SHARED_RECOVERY_DEVELOPMENT=1)
endif
ifeq ($(ABI3_DEVELOPMENT),1)
ifneq ($(SHARED_RECOVERY_DEVELOPMENT),1)
ifeq ($(filter %:abi3-development,$(IMAGE)),)
$(error ABI3_DEVELOPMENT requires explicit IMAGE ending :abi3-development)
endif
endif
else ifneq ($(ABI3_DEVELOPMENT),0)
$(error ABI3_DEVELOPMENT must be 0 or 1)
endif
.PHONY: build
# Keep the actual full fact-acquisition implementation shared. This profile is
# experimental and has no production/native Ready claim until integrated proof.
build:
	@set -eu; context=$$(mktemp -d); trap 'rm -rf "$$context"' EXIT; \
	mkdir -p "$$context/full" "$$context/fullruntime/bpf"; \
	./shared-build-profile.sh defines > "$$context/program.bpf.c"; \
	printf '%s\n' '#define ENFORCE_EXEC_PERSISTENT_OWNER 1' '#include "full/program.bpf.c"' >> "$$context/program.bpf.c"; \
	cp ../program.bpf.c ../stdio.h ../filesystem.h ../image_origin.h ../owner_types.h ../owner_control.h ../owner_roles.h ../epoch_roles.h ../shared_arena.h ../shared_snapshot.h ../shared_route.h ../shared_control.h ../shared_policy_lookup.h ../shared_policy_physical_kernel.h ../shared_exec.h ../shared_inherit_snapshot.h ../shared_policy_prepare.h ../shared_invocation_wire.h ../shared_kernel.h ../shared_task_identity.h ../shared_inode_facts.h ../shared_inode_kernel.h ../shared_recovery_abi.h ../shared_recovery_transition.h ../shared_recovery_kernel.h ../shared_arm_abi.h ../shared_catalogue_wire.h ../shared_catalogue_kernel.h ../shared_publication_arm.h ../shared_image.h ../shared_image_kernel.h "$$context/full/"; \
	cp ../../fullpolicy/bpf/matcher.h ../../fullpolicy/bpf/evaluator.h "$$context/full/"; \
	cp ../../fullruntime/bpf/gate.h "$$context/fullruntime/bpf/"; \
	cp gadget.yaml "$$context/"; \
	if [ "$(ABI3_DEVELOPMENT)" = 1 ]; then \
	    sed -i '1i#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1' "$$context/program.bpf.c"; \
	    sed -i 's/enforce-exec-owner-abi: "2"/enforce-exec-owner-abi: "3"\n  enforce-exec-owner-development: "true"/; s/^description:.*/description: "Stage A ABI3 development only; incomplete lifecycle, not production-ready"/' "$$context/gadget.yaml"; \
	fi; \
	if [ "$(SHARED_RECOVERY_DEVELOPMENT)" = 1 ]; then \
	    sed -i 's/^description:.*/description: "Shared ABI3 recovery development only; native supervisor and enforcement unavailable"/' "$$context/gadget.yaml"; \
	fi; \
	./shared-build-profile.sh metadata > "$$context/shared-annotations"; \
	sed -i '/^annotations:/r '"$$context/shared-annotations" "$$context/gadget.yaml"; \
	$(IG) image build -t "$(IMAGE)" "$$context"

# Explicit supported amd64 path; does not use/upgrade the default IG builder.
# VMLINUX_BTF must be a trusted artifact matching an exact fullruntime kernel matrix digest.
# Requires Clang 21.1.8; does not load BPF or claim arm64/general kernel support.
# Example: make archive VMLINUX_BTF=/trusted/vmlinux.btf \
#   IMAGE=localhost/enforce-exec-owner:abi2 ARCHIVE=/tmp/owner.tar
CLANG ?= clang-21
BPFTOOL ?= bpftool
VMLINUX_BTF ?=
ARCHIVE ?=
export CLANG BPFTOOL VMLINUX_BTF IMAGE ARCHIVE ABI3_DEVELOPMENT SHARED_RECOVERY_DEVELOPMENT
.PHONY: archive
archive:
	@./build-archive.sh "$$VMLINUX_BTF" "$$CLANG" "$$BPFTOOL" "$$IMAGE" "$$ARCHIVE"
