#!/usr/bin/env python3
"""Copies payload size and hashes from pack.py's metadata.json into plugin.json
and points payload_url at the GitHub release for the manifest's version."""
import json
import re
import sys
from pathlib import Path

manifest_path, metadata_path = Path(sys.argv[1]), Path(sys.argv[2])
metadata = json.loads(metadata_path.read_text())
manifest = json.loads(manifest_path.read_text())
manifest.update({
    "payload_size": metadata["compressed"],
    "payload_sha256": metadata["sha256"],
    "expanded_size": metadata["expanded"],
    "expanded_sha256": metadata["expanded_sha256"],
    "member_count": metadata["files"],
})
manifest["payload_url"] = re.sub(r"/download/v[^/]+/", f"/download/v{manifest['version']}/",
                                 manifest["payload_url"])
manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
