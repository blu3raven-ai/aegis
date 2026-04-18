# Scanner Image Changes Required

Each scanner image (sca-scanner, secret-scanner, sast-scanner, container-scanner) needs:

## 1. Add scanner user (Dockerfile)
```dockerfile
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner
RUN mkdir -p /home/scanner/.cache/grype /home/scanner/.cache/trivy && \
    chown -R 1000:1000 /home/scanner/.cache
USER 1000
```

## 2. Copy manifest.py
```dockerfile
COPY manifest.py /scanner/manifest.py
```

## 3. Update entrypoint
```python
from manifest import get_output_dir, record_output, record_done

output_dir = get_output_dir()  # reads JOB_ID env var

for repo in repos:
    # ... scan repo ...
    output_path = f"{output_dir}/grype-{repo_name}.json"
    # ... write output file ...
    record_output(output_dir, output_path, repo_name)

record_done(output_dir, len(repos))
```

## 4. New env var
- `JOB_ID` — provided by runner, used to namespace output directory
