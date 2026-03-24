# intelowl-poc-8

Small ast passes over a local IntelOwl checkout for idea #8 (connectors). No Django import — just pathlib/ast/re.

I usually point this at whatever’s on `develop`; last time I pinned the sample report to `5619186e`.

Scans: connector subclasses vs `health_check`, dumb `.replace()` exprs, OpenCTI ctor without `timeout`, PyMISP timeouts under a fixed cutoff, `EmailSender.update`, whether `MockPyMISP` implements `get_version`, Yeti `api/v2` strings, pins in requirements, connector tests whose names contain `run`. The two `*_prototype.py` files are scratch (MISP health_check shape, OpenCTI error copy). MISP prototype only talks to the network if you pass url/key and have pymisp.

```bash
cd intelowl-poc-8

uv run scripts/scan_connectors.py /path/to/IntelOwl

uv run scripts/generate_connector_report.py \
  --intelowl-root /path/to/IntelOwl \
  --output reports/connector_audit_report.md

bash scripts/smoke_test.sh /path/to/IntelOwl
```

`reports/connector_audit_sample.md` is a frozen run. `patches/misp_hash_type_fix.patch` is the `.replace()` fix sketched as a diff.

Still not a substitute for hitting real MISP/OpenCTI. Open questions for maintainers live next to the proposal in `maintainer_questions.md`.
