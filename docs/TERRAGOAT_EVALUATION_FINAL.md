# TerraGoat Evaluation (Final)

Date: 2026-03-12

## Scope

- Target benchmark: TerraGoat AWS Terraform (`benchmark/terragoat/terraform/aws`)
- Pipeline: RECON -> HUNT -> CHAIN -> PROVE -> REMEDIATE
- Depth profile used: `quick`
- Severity threshold: `low`

## Key Runs

### Scan 2 (fixed parser + original prompts)

- Execution: `exec_20260312_033236_at5hg77c`
- Total resources: 68
- Raw findings: 35
- Confirmed: 10
- Attack paths: 3
- Duration: ~23 min
- Coverage (mapped): 23/49 = 46.9%

### Scan 3 (V1 meta prompts + compute hunter)

- Execution: `exec_20260312_041237_fbjd66qy`
- Total resources: 68
- Raw findings: 45
- Confirmed: 20
- Attack paths: 3
- Duration: 2649.2s (~44.2 min)
- Coverage (mapped): 33/49 = 67.3%

### Scan 4 (V2 abstract meta reasoning prompts)

- Execution: `exec_20260312_050217_gycqlg0x`
- Total resources: 68
- Raw findings: 41
- Confirmed: 20
- Attack paths: 3
- Duration: 2148.6s (~35.8 min)
- Coverage (mapped): 25/49 = 51.0%

## Final Assessment

- Best benchmark performance in this cycle: **Scan 3**
  - 67.3% mapped coverage (33/49)
  - 20 confirmed findings with strong exploitability validation
- Scan 4 improved abstraction style but reduced benchmark recall versus Scan 3.

## Category Notes (Best-Observed in Cycle)

- Strong: Secrets, network ingress/exposure, RDS core risks, Neptune encryption, KMS rotation, EBS encryption.
- Weak / recurring misses: S3 absent-feature sweep (logging/versioning/ACL across all buckets), ES version/encryption depth, ECR scanning, ELB access logs, IAM permission boundary edge cases.

## Conclusion

For the current finalized version, the benchmark result to report is:

- **CloudProve-AF TerraGoat coverage: 33/49 (67.3%)**
- **Confirmed findings: 20**
- **Attack paths: 3**

This is the final evaluation snapshot for this iteration.
