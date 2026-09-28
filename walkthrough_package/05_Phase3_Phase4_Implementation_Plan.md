# Implementation Plan — Phase 4 Final Blocker Audit

## Overview
Perform a read-only technical audit of **Phase 4 — Advanced Threat Intelligence, Threat Correlation & Security Investigation Layer**.

The audit will inspect source code implementations across 10 critical verification areas, execute automated tests, audit API backward compatibility, measure regression test performance, and output a structured audit report with clear PASS / FAIL / WARNING ratings and a final recommendation (`FREEZE PHASE 4` or `DO NOT FREEZE PHASE 4`).

---

## Audit Execution & Inspection Plan

### 1. MITRE ATT&CK Mapping Audit (`ml/mitre/attack_mapper.py`)
- Inspect `MITREAttackMapper.map_event()`:
  - Verify `BOTNET` and `INFILTRATION` labels evaluate port/protocol evidence before technique assignment, returning `NO_CONFIDENT_MAPPING` when evidence is insufficient.
  - Verify mapping fields (`technique_id`, `technique_name`, `tactic`, `confidence`, `reason`, `evidence`, `mapping_basis`).
  - Verify explicit disclaimers regarding attacker intent.

### 2. Risk Scoring Audit (`ml/risk/risk_engine.py`)
- Inspect `RiskEngine.calculate_risk()`:
  - Verify 5 normalized 0-100 components (`confidence_score`, `anomaly_score`, `severity_score`, `intel_score`, `correlation_score`).
  - Verify weights ($0.25 + 0.20 + 0.25 + 0.15 + 0.15 = 1.0$).
  - Verify score clamping to $[0.0, 100.0]$.
  - Verify documentation of explainable engineering score semantics.

### 3. Correlation Engine & Entity Strength Audit (`ml/correlation/`)
- Inspect `entity_tracker.py` & `correlation_engine.py`:
  - Verify entity strength hierarchy (`EXACT_ENTITY` $>$ `STRONG` $>$ `MODERATE` $>$ `WEAK`).
  - Verify subnet membership is classified as `WEAK` and not treated as proof of the same attacker.
  - Verify configurable temporal window (default 300s).

### 4. Attack Chain & Stage Status Audit (`ml/correlation/attack_chain.py`)
- Inspect `AttackChainBuilder.build_chain()`:
  - Verify stage status assignments (`OBSERVED`, `CORRELATED`, `INFERRED`, `UNKNOWN`).
  - Verify attack sequence is dynamic and not hardcoded.

### 5. Threat Intelligence & Offline Mode Audit (`ml/threat_intelligence/`)
- Inspect `intel_provider.py`, `enrichment_engine.py`, `cache.py`:
  - Verify 100% offline operation when no API keys are present.
  - Verify API key masking (no keys in responses/logs).
  - Verify cache TTL behavior.

### 6. IOC Extraction Audit (`ml/threat_intelligence/ioc_extractor.py`)
- Inspect `extract_iocs()`:
  - Verify handling of IPv4, IPv6, Domain, URL, Port, Protocol, and Hash.
  - Verify safety on malformed indicators.

### 7. Persistence Audit (`ml/investigation/incident_manager.py`)
- Verify lightweight SQLite/in-memory persistence without requiring external infrastructure.

### 8. API Backward Compatibility Audit (`m4_threat_classifier/api/routes.py`)
- Test `POST /api/v1/detect`, `/api/v1/health`, `POST /api/v1/investigations/events`, `GET /api/v1/incidents`, `GET /api/v1/iocs/<ioc>`.

### 9. Regression & Test Suite Execution
- Run `pytest` and report test counts, passed/failed stats, execution time, and coverage gaps.

### 10. Documentation Verification (`ml/reports/phase4_investigation_report.md`)
- Audit report contents against Phase 4 requirements.

---

## Verification Plan

### Automated Test Execution
```bash
cd "C:\PROJECTS\SIH PS145\AaYuushman's work"
pytest
```
