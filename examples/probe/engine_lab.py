"""Explicit development lab: pinned engines consume ONLY a generated benign PCAP.

Containers have no network, capture capabilities, host devices or Docker socket.
Images must already be installed; this script never pulls an image or runs live capture.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import time
from pathlib import Path

from safecadence.integrations.probe import ProbeCollector, ProbeSpool, canonical
from cryptography.fernet import Fernet
from datetime import datetime, timedelta, timezone
import hmac

ZEEK = "zeek/zeek@sha256:703f0b22af150d9418739b2a012fbfb5d01ee004aded3bd43b0175010db05928"
SURICATA = "jasonish/suricata@sha256:8058c0580c48cae4013bb8d576e5fe7cfe59884ea5526239056825b70c849ec8"


def pcap():
    payload = b"NETRISK_BENIGN_FIXTURE"
    udp = struct.pack("!HHHH", 9999, 9999, len(payload) + 8, 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         bytes([10, 10, 10, 1]), bytes([10, 10, 20, 2]))
    total = sum(struct.unpack("!10H", header))
    total = (total & 65535) + (total >> 16)
    header = header[:10] + struct.pack("!H", (~total) & 65535) + header[12:]
    frame = bytes.fromhex("0200000000020200000000010800") + header + udp
    return (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
            struct.pack("<IIII", int(time.time()), 0, len(frame), len(frame)) + frame)


def run(image, root, entrypoint, args):
    if not re.fullmatch(r"(?:zeek/zeek|jasonish/suricata)@sha256:[a-f0-9]{64}", image):
        raise ValueError("A reviewed digest-pinned engine image is required")
    command = ["docker", "run", "--rm", "--pull=never", "--network=none", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--read-only", "--pids-limit=128", "--cpus=1", "--memory=768m",
               "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m", "--mount=type=bind,src=" + str(root) + ",dst=/work",
               "--workdir=/work", "--entrypoint=" + entrypoint, image, *args]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Offline engine failed: " + result.stderr[-2000:] + result.stdout[-2000:])
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / "fixture.pcap").write_bytes(pcap())
    (root / "benign.rules").write_text('alert udp any any -> any 9999 (msg:"NetRisk benign offline fixture"; content:"NETRISK_BENIGN_FIXTURE"; sid:9000001; rev:1;)\n')
    (root / "suricata").mkdir()
    (root / "suricata.yaml").write_text("""%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.10.10.0/24,10.10.20.0/24]"
    EXTERNAL_NET: any
default-log-dir: /work/suricata
rule-files:
  - /work/benign.rules
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, flow, stats]
stats:
  enabled: yes
  interval: 1
""")
    versions = dict(zeek=run(ZEEK, root, "/usr/local/zeek/bin/zeek", ["--version"]),
                    suricata=run(SURICATA, root, "/usr/bin/suricata", ["-V"]))
    run(ZEEK, root, "/usr/local/zeek/bin/zeek", ["-r", "/work/fixture.pcap", "LogAscii::use_json=T"])
    run(SURICATA, root, "/usr/bin/suricata", ["--runmode=single", "-c", "/work/suricata.yaml", "-l", "/work/suricata", "-r", "/work/fixture.pcap"])
    zeek = [json.loads(line) for line in (root / "conn.log").read_text().splitlines() if line.strip()]
    eve = [json.loads(line) for line in (root / "suricata/eve.json").read_text().splitlines() if line.strip()]
    assert zeek and any(e.get("alert", {}).get("signature_id") == 9000001 for e in eve)
    (root / "auth.hex").write_text("12" * 32)  # Explicit fixture-only key, never production enrollment.
    (root / "spool.key").write_bytes(Fernet.generate_key())
    for name in ("auth.hex", "spool.key"):
        (root / name).chmod(0o600)
    config = dict(probe_id="synthetic-probe", tenant="lab", site="synthetic", segment="two-subnets",
                  instance="engine-lab", source_version="offline-engine-lab", sources=["zeek", "suricata"])
    queue = ProbeSpool(root / "spool.db", config=config, encryption_key_file=root / "spool.key")
    collector = ProbeCollector(root / "collector.db")
    enrolled = dict(config, enabled=True, certificate_sha256="a" * 64, auth_key_file=str(root / "auth.hex"),
                    expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    try:
        queue.stage(canonical(zeek), source="zeek")
        queue.stage(canonical(eve), source="suricata")
        while queue.pending():
            seq, body, batch_hash = queue.pending()
            signature = hmac.new(bytes.fromhex("12" * 32), body, hashlib.sha256).hexdigest()
            receipt = collector.accept(body, signature, enrollment=enrolled, certificate_sha256="a" * 64)
            queue.acknowledge(seq, batch_hash, receipt)
        report = dict(status="passed", versions=versions, images={"zeek": ZEEK, "suricata": SURICATA},
                      source_records={"zeek": len(zeek), "suricata": len(eve)},
                      evidence_records=len(collector.events(tenant="lab")), audit_valid=collector.audit(tenant="lab")["chain_valid"],
                      network="none", live_capture=False, hardware_qualified=False,
                      limitation="One generated UDP packet. Not throughput, mirror/TAP, hardware or field qualification.")
        (root / "result.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    finally:
        queue.close()
        collector.close()


if __name__ == "__main__":
    main()
