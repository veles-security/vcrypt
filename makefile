PWD := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
REPORT_DIR := test/reports/sast

.PHONY: sast-gosec sast-govulncheck sast-semgrep  sast test image-push

.IGNORE: sast-gosec sast-govulncheck sast-semgrep 

sast-gosec:
	@mkdir -p $(REPORT_DIR)
	@docker run --rm -it -v "$(PWD)":/workspace -w /workspace securego/gosec:2.24.7 -out $(REPORT_DIR)/gosec.txt ./...
	@echo "SAST gosec completed"

sast-govulncheck:
	@mkdir -p $(REPORT_DIR)
	@docker run --rm -v "$(PWD)":/app -w /app golang:1.26.7 go mod download && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./... >$(REPORT_DIR)/govulncheck.txt
	@echo "SAST govulncheck completed"

sast-semgrep:
	@mkdir -p $(REPORT_DIR)
	@docker run --rm -v "$(PWD)":/src -w /src semgrep/semgrep semgrep --config=auto --exclude=internal/testkeys/testdata --text > $(REPORT_DIR)/semgrep.txt 2>&1
	@echo "SAST semgrep completed"

sast: sast-gosec sast-govulncheck sast-semgrep 
	@echo "SAST completed"
