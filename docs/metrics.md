# Metrics

Yubistack metrics are pushed through prometheus. Currently all metrics are
centralized in [this file](../cmd/prometheus.go).

Here are their definitions:

| Metric name                            | Metric type | Labels/tags                          | Status |
| -------------------------------------- | ----------- | ------------------------------------ | ------ |
| pps_yubistack_decrypt_duration_seconds | Histogram   | `code`=&lt;200&vert;400&vert;500&gt; | DEV    |
| pps_yubistack_sync_duration_seconds    | Histogram   | `code`=&lt;200&vert;400&vert;500&gt; | DEV    |
| pps_yubistack_auth_duration_seconds    | Histogram   | `code`=&lt;200&vert;400&vert;500&gt; | DEV    |
