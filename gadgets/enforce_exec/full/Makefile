IG ?= ig
IMAGE ?= enforce-exec-full:experimental
.PHONY: build
build:
	@set -eu; context=$$(mktemp -d); trap 'rm -rf "$$context"' EXIT; \
	cp program.bpf.c stdio.h image_origin.h filesystem.h gadget.yaml "$$context/"; \
	cp ../fullpolicy/bpf/matcher.h ../fullpolicy/bpf/evaluator.h "$$context/"; \
	$(IG) image build -t "$(IMAGE)" "$$context"
