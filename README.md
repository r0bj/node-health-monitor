# Node Health Monitor

Node Health Monitor is a Go-based service designed to monitor the health of nodes by periodically checking their health endpoints. It provides HTTP endpoints for health checks, exposes Prometheus metrics for monitoring, and supports caching to optimize performance.

When deploying Node Health Monitor to Kubernetes, ensure that the service targeting the monitor has .spec.externalTrafficPolicy set to Local. This configuration ensures that external traffic is routed only to pods on the same node.
