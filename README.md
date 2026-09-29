# egypt-asn-collector-src

Source + Dockerfile for the Egyptian-ASN prefix collector. This is a plain
image-source repo — no Helm chart, no Fleet manifest. It just builds and
pushes the container image that the `egypt-asn-feed` GitOps chart deploys.

- `egypt_asn_collector.py` — collector script (RIPEstat + bgpview.io fallback)
- `Dockerfile` — `python:3.12-slim` + requests
- `.github/workflows/build-image.yaml` — builds/pushes to
  `ghcr.io/<org>/egypt-asn-collector:latest` and `:<sha>` on push to `main`

If you'd rather build via your Gitea act_runner pipeline (same as
RustDesk/BetterDesk) instead of GitHub Actions, drop the `.github/`
workflow and add the equivalent `.gitea/workflows` or act_runner job —
the Dockerfile itself doesn't change either way.

After building, point the `egypt-asn-feed` chart's `values.yaml` at the
resulting image:

```yaml
image:
  repository: ghcr.io/<org>/egypt-asn-collector
  tag: latest   # or a pinned :<sha>
```
