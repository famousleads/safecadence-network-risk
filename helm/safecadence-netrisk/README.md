# safecadence-netrisk Helm chart

Deploy SafeCadence NetRisk on Kubernetes.

## Install

```
helm repo add safecadence https://famousleads.github.io/charts
helm install netrisk safecadence/safecadence-netrisk \
  --namespace safecadence --create-namespace \
  --set ingress.host=safecadence.example.com \
  --set secrets.SC_PORTAL_SECRET=$(openssl rand -hex 32)
```

Or install directly from this directory:

```
helm install netrisk ./helm/safecadence-netrisk -n safecadence --create-namespace
```

## Values

See `values.yaml`. Highlights:

| Key | Default | Notes |
|---|---|---|
| `replicaCount` | `1` | Increase for HA (requires shared `/data` or Postgres). |
| `image.tag` | `11.2.0` | Pin in prod. |
| `ingress.enabled` | `true` | Set `ingress.host` for your domain. |
| `ingress.tls.enabled` | `true` | TLS via cert-manager. |
| `persistence.enabled` | `true` | PVC for `/data`. Set `false` for stateless demos. |
| `postgres.enabled` | `true` | Bundled in-cluster Postgres. Set `false` and point `env.SC_DATABASE_URL` at external. |
| `redis.enabled` | `true` | Bundled in-cluster Redis. |
| `secrets.*` | `""` | Surfaced through a Kubernetes Secret; populate before deploy. |

## Upgrade

```
helm upgrade netrisk ./helm/safecadence-netrisk -n safecadence
```

## Uninstall

```
helm uninstall netrisk -n safecadence
```

## License

MIT
