# IntelOwl Connector Ecosystem Audit (static PoC)

**Generated:** 2026-03-22 22:38
**IntelOwl commit:** `5619186e` (`develop`)
**Scope:** Static analysis of `api_app/connectors_manager/connectors/`, requirements, and `tests/api_app/connectors_manager/`

This report supports **GSoC Idea #8** (Integration Ecosystem & Connector Optimization): known antipatterns, dependency pins, generic health checks, and test surface.

---

## 1. Executive summary

- **Connector classes scanned:** 6 (`api_app/connectors_manager/connectors/*.py`).
- **`health_check` overrides:** 0 (expected: 0 until connector-specific health work lands).
- **Discarded `.replace()` calls:** 1 (see §3 — includes the MISP hash-type bug pattern).
- **AbuseSubmitter imports `AnalyzerRunException`:** yes (see §5)
- **Dependency pins:** `pymisp==2.5.0` (project-requirements), `pycti==6.8.8` (hardcoded-requirements / Docker).
- **Connector manager tests:** 3 files, ~304 lines; tests with `run` in the name: 1 hit(s).
- **OpenCTI `OpenCTIApiClient` without `timeout`:** 1 call site(s) (stalled server can hang the worker; same class of issue as [issue #3495](https://github.com/intelowlproject/IntelOwl/issues/3495)).
- **PyMISP `timeout` ≤10s:** 1 (explicit short client timeout — see `PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC` in `scan_connectors.py`).
- **`EmailSender.update()` stub:** `api_app/connectors_manager/connectors/email_sender.py:45` (annotated `-> bool` but body is `pass` → returns `None`).
- **`MockPyMISP.get_version`:** **missing** (extend mock when MISP health check calls `get_version`).

---

## 2. Connector inventory & health checks

| Class | File | `health_check` override |
|-------|------|-------------------------|
| `AbuseSubmitter` | `api_app/connectors_manager/connectors/abuse_submitter.py` | **no** (inherits generic `Plugin.health_check`) |
| `EmailSender` | `api_app/connectors_manager/connectors/email_sender.py` | **no** (inherits generic `Plugin.health_check`) |
| `MISP` | `api_app/connectors_manager/connectors/misp.py` | **no** (inherits generic `Plugin.health_check`) |
| `OpenCTI` | `api_app/connectors_manager/connectors/opencti.py` | **no** (inherits generic `Plugin.health_check`) |
| `Slack` | `api_app/connectors_manager/connectors/slack.py` | **no** (inherits generic `Plugin.health_check`) |
| `YETI` | `api_app/connectors_manager/connectors/yeti.py` | **no** (inherits generic `Plugin.health_check`) |

### 2.1 Generic `health_check` (reference)

Connectors inherit `Plugin.health_check` → `requests.head(url, verify=False)` and treat some 4xx as success (auth may hide real failures). Snippet from `api_app/classes.py`:

```text
 358 |     def health_check(self, user: User = None) -> bool:
 359 |         """
 360 |         Perform a health check for the plugin.
 361 | 
 362 |         Args:
 363 |             user (User): The user instance.
 364 | 
 365 |         Returns:
 366 |             bool: Whether the health check was successful.
 367 |         """
 368 |         url = self._get_health_check_url(user)
 369 |         if url and url.startswith("http"):
 370 |             if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
 371 |                 return True
 372 |             logger.info(f"healthcheck url {url} for {self}")
 373 |             try:
 374 |                 # momentarily set this to False to
 375 |                 # avoid fails for https services
 376 |                 response = requests.head(url, timeout=10, verify=False)
 377 |                 # This may happen when even the HEAD request is protected by authentication
 378 |                 # We cannot create a generic health check that consider auth too
 379 |                 # because every analyzer has its own way to authenticate
 380 |                 # So, in this case, we will consider it as check passed because we got an answer
 381 |                 # For ex 405 code is when HEADs are not allowed. But it is the same. The service answered.
 382 |                 if 400 <= response.status_code <= 408:
 383 |                     return True
 384 |                 response.raise_for_status()
 385 |             except (
 386 |                 requests.exceptions.ConnectionError,
 387 |                 requests.exceptions.Timeout,
 388 |                 requests.exceptions.HTTPError,
 389 |             ) as e:
 390 |                 logger.info(f"healthcheck failed: url {url} for {self}. Error: {e}")
 391 |                 return False
 392 |             else:
 393 |                 return True
 394 |         raise NotImplementedError()
 395 |
```

---

## 3. Discarded string `.replace()` (bug pattern)

Calling `matched_type.replace(...)` without assigning the result leaves hash type strings like `sha-256` unchanged for MISP.

| File | Line | Snippet |
|------|------|---------|
| `api_app/connectors_manager/connectors/misp.py` | 65 | `matched_type.replace("-", "")  # convert sha-x to shax` |


---

## 4. HTTP client timeouts & MISP test doubles

### 4.1 `OpenCTIApiClient` without `timeout`

| File | Line |
|------|------|
| `api_app/connectors_manager/connectors/opencti.py` | 112 |

### 4.2 `PyMISP` aggressive `timeout` (≤ 10s)

Threshold rationale: only flag explicit `timeout=` values ≤10s (multi-step MISP operations on busy instances routinely exceed a few seconds; see constant comment in `scan_connectors.py`).

| File | Line | Seconds |
|------|------|---------|
| `api_app/connectors_manager/connectors/misp.py` | 102 | 5 |

### 4.3 `EmailSender.update()`

`api_app/connectors_manager/connectors/email_sender.py:45` — `def update(self) -> bool: pass` returns `None` at runtime.

### 4.4 `MockPyMISP` vs future `get_version()` health check

`MockPyMISP` does **not** define `get_version`. When MISP `health_check` calls `PyMISP.get_version()`, extend this mock (Phase 2) so `_monkeypatch()` tests keep passing.

---

## 5. AbuseSubmitter exception hierarchy

`api_app/connectors_manager/connectors/abuse_submitter.py` imports `AnalyzerRunException` from analyzers. Connectors should raise `ConnectorRunException` for consistent error handling / UI.

---

## 6. Yeti: connector vs analyzer URL paths

[Issue #2309](https://github.com/intelowlproject/IntelOwl/issues/2309) (Yeti API drift) may affect analyzer and connector differently. Current `api/v2` fragments found:

| File | Line | Fragment |
|------|------|----------|
| `api_app/connectors_manager/connectors/yeti.py` | 51 | `{self._url_key_name}/api/v2/observables/` |
| `api_app/analyzers_manager/observable_analyzers/yeti.py` | 25 | `{self._url_key_name}/api/v2/observables/search/` |

---

## 7. Tests mentioning `run` (connectors_manager)

| File | Line | Line preview |
|------|------|--------------|
| `tests/api_app/connectors_manager/test_classes.py` | 55 | `def test_before_run(self):` |

Per `proposal_research_notes.md`, there are still no dedicated unit tests for each connector `run()` mapping/payloads — this scan does not prove absence; it only lists naming hits.

---

## 8. Maintainer questions (Idea #8)

Cross-check with `IntelOwl/maintainer_questions.md`: OpenCTI/pycti target versions, authenticated health checks, CI budget for integration tests, mock-based OpenCTI tests.
