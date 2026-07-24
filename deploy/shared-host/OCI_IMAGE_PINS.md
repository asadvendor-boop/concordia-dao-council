# External OCI image pins

The shared-host release uses immutable multi-platform registry-index digests.
The inspection below was performed on 2026-07-24 without downloading image
layers or starting containers.

| Upstream tag | Pinned index digest | `linux/amd64` child | `linux/arm64` child |
| --- | --- | --- | --- |
| `ipfs/kubo:v0.32.1` | `sha256:7cc0e0de8f845d6c9fa1dce414c069974c34ed3cd3742e0d4f5bccda4adc376d` | `sha256:5b55e60dbe79e047ccfa58d6ac6640b81e9fab60d5a3ee10e7a4ccd9a1f1239f` | `sha256:56f431f60aab998175f12f0b55e8575873964074f6fe54721f97e41f086a8b7d` |
| `otel/opentelemetry-collector-contrib:0.114.0` | `sha256:37fa87091cfaaec7234a27e4e395a40c31c2bfaea97a349a4afef6d9e9681197` | `sha256:94ac10da6c15fdad4f8091c4292a8c6814b467cd3bcf575ba2279e9dc6346e63` | `sha256:6ef963ce0e97d0e69f5284b4b171a483978098d1540c89af34c9230cfd844054` |
| `jaegertracing/all-in-one:1.62.0` | `sha256:836e9b69c88afbedf7683ea7162e179de63b1f981662e83f5ebb68badadc710f` | `sha256:53d140774b407d5e2a1b4eed556f1852595fc39e14b24acbceaf7e36691f3a60` | `sha256:9da7c1cea6ab2dd9fe71712b151db257c4bee72c35aa8eff81477c2f51743942` |

The pinned indexes include both supported Linux host architectures. Before a
release, map `uname -m` strictly: `x86_64` selects `linux/amd64`; `aarch64`
selects `linux/arm64`; any other value stops the release.

## Reproduction

Inspect the registry index and its declared platforms:

```bash
docker buildx imagetools inspect ipfs/kubo:v0.32.1
docker buildx imagetools inspect otel/opentelemetry-collector-contrib:0.114.0
docker buildx imagetools inspect jaegertracing/all-in-one:1.62.0
```

Hash the exact raw index bytes and list the compatible Linux manifests:

```bash
for image in \
  ipfs/kubo:v0.32.1 \
  otel/opentelemetry-collector-contrib:0.114.0 \
  jaegertracing/all-in-one:1.62.0
do
  docker buildx imagetools inspect --raw "${image}" | shasum -a 256
  docker buildx imagetools inspect --raw "${image}" |
    jq -r '.manifests[] | select(.platform.os=="linux" and
      (.platform.architecture=="amd64" or .platform.architecture=="arm64")) |
      [.digest,.mediaType,.platform.os,.platform.architecture] | @tsv'
done
```

The Compose file references the index digests, so tag movement cannot alter the
selected bytes. The runtime release capture still records the resolved child
manifest and container image identifiers.
