# Connectors — static dump

IntelOwl `5619186e` on `develop` · 2026-03-22 22:38. Scanned `connectors/`, requirement pins, connector tests.

## Summary

- 6 connector classes under `connectors/`; 0 override `health_check`.
- 1 bad `.replace()` (no assign) — MISP hash line if anything shows up below.
- abuse_submitter pulls `AnalyzerRunException` from analyzers: yes.
- pins: pymisp==2.5.0, pycti==6.8.8
- connector tests: 3 files / ~304 lines; 1 test names contain `run`.
- OpenCTI client calls without `timeout`: 1
- PyMISP with timeout ≤10s: 1 (threshold is `PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC` in scan_connectors.py)
- EmailSender.update is a stub: `api_app/connectors_manager/connectors/email_sender.py:45`
- MockPyMISP.get_version: no

## Connector classes

| Class | File | `health_check` override |
|-------|------|-------------------------|
| `AbuseSubmitter` | `api_app/connectors_manager/connectors/abuse_submitter.py` | **no** (inherits generic `Plugin.health_check`) |
| `EmailSender` | `api_app/connectors_manager/connectors/email_sender.py` | **no** (inherits generic `Plugin.health_check`) |
| `MISP` | `api_app/connectors_manager/connectors/misp.py` | **no** (inherits generic `Plugin.health_check`) |
| `OpenCTI` | `api_app/connectors_manager/connectors/opencti.py` | **no** (inherits generic `Plugin.health_check`) |
| `Slack` | `api_app/connectors_manager/connectors/slack.py` | **no** (inherits generic `Plugin.health_check`) |
| `YETI` | `api_app/connectors_manager/connectors/yeti.py` | **no** (inherits generic `Plugin.health_check`) |

### Default health_check

Everyone inherits this unless overridden — `requests.head`, `verify=False`, some 4xx counted as fine. Snippet:

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

## Stray .replace()

Expr-statement `.replace()` without assignment — leaves e.g. `sha-256` as-is for MISP.

| File | Line | Snippet |
|------|------|---------|
| `api_app/connectors_manager/connectors/misp.py` | 65 | `matched_type.replace("-", "")  # convert sha-x to shax` |


---

## Timeouts + test doubles

### OpenCTI client, no timeout kw

| File | Line |
|------|------|
| `api_app/connectors_manager/connectors/opencti.py` | 112 |

### PyMISP timeout ≤10s

Arbitrary cutoff at 10s — see constant in scan_connectors.py.

| File | Line | Seconds |
|------|------|---------|
| `api_app/connectors_manager/connectors/misp.py` | 102 | 5 |

### EmailSender.update

`api_app/connectors_manager/connectors/email_sender.py:45` — `def update(self) -> bool: pass` returns `None`.

### MockPyMISP.get_version

`MockPyMISP` has no `get_version`; add it if `health_check` starts calling the real API.

---

## AbuseSubmitter import

`api_app/connectors_manager/connectors/abuse_submitter.py` imports `AnalyzerRunException` from analyzers. Probably should use `ConnectorRunException` like the rest of connectors.

---

## Yeti urls

Anything with `api/v2` in the connector vs analyzer files ([#2309](https://github.com/intelowlproject/IntelOwl/issues/2309)):

| File | Line | Fragment |
|------|------|----------|
| `api_app/connectors_manager/connectors/yeti.py` | 51 | `{self._url_key_name}/api/v2/observables/` |
| `api_app/analyzers_manager/observable_analyzers/yeti.py` | 25 | `{self._url_key_name}/api/v2/observables/search/` |

---

## Tests with "run" in the name

| File | Line | Line preview |
|------|------|--------------|
| `tests/api_app/connectors_manager/test_classes.py` | 55 | `def test_before_run(self):` |

Just filename/grep style hits, not a real map of run() coverage.

## Random questions

Left the detailed list in maintainer_questions.md (pycti vs server, real health checks, how much CI time, etc.).
