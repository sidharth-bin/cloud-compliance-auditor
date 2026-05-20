#!/usr/bin/env python3
"""
Module Name:    auditor.py
Description:    Production-Grade Cross-Platform Infrastructure Configuration Compliance Auditor
Author:         Sidharth (sidharth-bin)
Architecture:   Decoupled rule validation array engine, zero-dependency container safety check
"""

import json
import os
import sys

class InfrastructureComplianceAuditor:
    def __init__(self):
        """Initializes baseline production security criteria metrics."""
        self.total_violations = 0
        self.files_evaluated = 0
        
        # High-ROI security baselines derived from enterprise hardening guides (CIS / OWASP)
        self.required_security_context = "runAsNonRoot: true"
        self.banned_privileged_flag = "privileged: true"
        self.required_read_only = "readOnlyRootFilesystem: true"

    def audit_yaml_manifest_compliance(self, file_path: str, raw_content: str) -> dict:
        """Parses individual infrastructure configuration streams line by line for flaws."""
        self.files_evaluated += 1
        findings = []
        is_privileged = False
        has_non_root_enforced = False
        has_read_only_enforced = False
        
        lines = raw_content.splitlines()
        for idx, line in enumerate(lines, start=1):
            clean_line = line.strip()
            
            # Metric 1: Track if container runs with broad dangerous root keys
            if self.banned_privileged_flag in clean_line and not clean_line.startswith("#"):
                findings.append({
                    "severity": "CRITICAL",
                    "line": idx,
                    "rule": "SEC-K8S-01",
                    "desc": "Container is allowed to operate in privileged mode. High risk of container breakout."
                })
                is_privileged = True
                
            # Metric 2: Look for non-root user isolation variables
            if self.required_security_context in clean_line and not clean_line.startswith("#"):
                has_non_root_enforced = True
                
            # Metric 3: Check for locked read-only operational file surfaces
            if self.required_read_only in clean_line and not clean_line.startswith("#"):
                has_read_only_enforced = True

        # Post-scan policy execution gates
        if not has_non_root_enforced:
            findings.append({
                "severity": "HIGH",
                "line": 1,
                "rule": "SEC-K8S-02",
                "desc": "Missing explicit user runtime boundaries. Container should enforce runAsNonRoot."
            })
        if not has_read_only_enforced:
            findings.append({
                "severity": "MEDIUM",
                "line": 1,
                "rule": "SEC-K8S-03",
                "desc": "Root file surface is writable. Best practice mandates a readOnlyRootFilesystem map."
            })

        self.total_violations += len(findings)
        
        # Calculate policy decisions deterministically
        status = "FAILED" if any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings) else "PASSED"
        
        return {
            "target_file": file_path,
            "policy_decision": status,
            "violations_found": len(findings),
            "vulnerabilities": findings
        }

if __name__ == "__main__":
    print("=== CLOUD COMPLIANCE ENGINE AUDIT RUNNING ===")
    auditor = InfrastructureComplianceAuditor()
    
    # High-grade target payload template simulating a weak infrastructure config layout
    unsecured_manifest_mock = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: production-payment-router
    spec:
      containers:
      - name: router-node
        image: payment-node:latest
        securityContext:
          privileged: true
          # runAsNonRoot: true
          # readOnlyRootFilesystem: true
    """
    
    print("[INFO] Processing local repository layout files against system policies...")
    report = auditor.audit_yaml_manifest_compliance("./deployments/payment-router.yaml", unsecured_manifest_mock)
    
    # Output cleanly structured compliance analytics data strings
    print("\n[COMPLIANCE INSIGHTS ENGINE REPORT]:")
    print(json.dumps(report, indent=2))
    print("\n---------------------------------------------------------")
    print(f"Total Workspace Elements Scanned: {auditor.files_evaluated}")
    print(f"Active Vulnerability Intercepts Tracked: {auditor.total_violations}")
    
    if auditor.total_violations > 0:
        print("RESULT: DEPLOYMENT GATE BLOCKED. Infrastructure violates compliance frameworks.")
        print("---------------------------------------------------------")
        sys.exit(1)
    else:
        print("RESULT: nominal state approved. Configuration meets security baselines.")
        print("---------------------------------------------------------")
        sys.exit(0)
