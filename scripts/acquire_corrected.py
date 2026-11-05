"""Download the user-approved public CNS2022 archive with a fixed size ceiling.

Run from the project root. This script does not extract archive members.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import urllib.request


URL = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
LIMIT = 450 * 1024 * 1024


def main():
    folder = Path(__file__).resolve().parent.parent / "data" / "cns2022"
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / "CICIDS2017_improved.zip"
    if archive.exists():
        raise ValueError(f"Archive already exists: {archive}; refusing overwrite")
    partial = archive.with_suffix(".zip.part")
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(URL, headers={"User-Agent": "attack-traffic-classifier-research/0.2"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.headers.get("Content-Length") and int(response.headers["Content-Length"]) > LIMIT:
            raise ValueError("Archive exceeds the approved download size ceiling")
        with partial.open("xb") as stream:
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > LIMIT:
                    raise ValueError("Download exceeded size ceiling; incomplete .part retained")
                stream.write(block)
                digest.update(block)
                if size % (32 * 1024 * 1024) == 0:
                    print(f"Downloaded {size // (1024 * 1024)} MiB", flush=True)
        headers = {key: response.headers.get(key) for key in ("Content-Length", "Last-Modified", "ETag", "Content-Type")}
    partial.rename(archive)
    record = {
        "variant": "corrected",
        "release": "CNS2022-CICIDS2017-improved-local-snapshot",
        "source_url": URL,
        "reference": "https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "file": archive.name,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "http_headers": headers,
        "license_status": "Usage/redistribution terms not yet verified; retain locally for research inspection",
    }
    (folder / "acquisition.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"archive": str(archive), "bytes": size, "sha256": digest.hexdigest()}))


if __name__ == "__main__":
    main()
