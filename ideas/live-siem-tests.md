# Live SIEM tests for Elastic and Sentinel

**Why.** Sigma output passes pySigma and SigmaHQ's validators; the Elastic (ES|QL) and Sentinel (KQL) queries are
checked for structure and against the reference evaluator, but have not run in a live stack.

**Approach.** Elastic: a throwaway Elasticsearch + Kibana in Docker, index the insider timeline (`examples/detections/`)
mapped to ECS, run each ES|QL query and compare hits with `usbhawk detections run --events`. Sentinel: the Log
Analytics demo workspace or a `datatable()` built from the same timeline, run each KQL query and compare. Record which
detections match and fix the generators where they do not.

**Tests.** An optional test marker that runs only when a stack URL is configured; documented results in
`docs/hunt-detection-rules.md`.
