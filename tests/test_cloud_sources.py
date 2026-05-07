"""
v9.6 — AWS/Azure/GCP cloud harvest tests.
Uses the json_text seam so tests don't shell out to aws/az/gcloud.
"""

from __future__ import annotations

import json
import pytest

from safecadence.discovery.cloud_harvest import (
    harvest_aws, harvest_azure, harvest_gcp,
    parse_aws_describe_instances, parse_az_vm_list, parse_gcloud_list,
    instances_as_discovered_hosts,
)


_AWS_JSON = json.dumps({
    "Reservations": [{
        "Instances": [
            {"InstanceId": "i-deadbeef01",
             "InstanceType": "t3.medium",
             "State": {"Name": "running"},
             "Placement": {"AvailabilityZone": "us-east-1a"},
             "PublicIpAddress": "54.10.20.30",
             "PrivateIpAddress": "10.0.1.42",
             "PlatformDetails": "Linux/UNIX",
             "LaunchTime": "2026-01-15T08:00:00.000Z",
             "Tags": [{"Key": "Name", "Value": "web-prod-01"},
                      {"Key": "env", "Value": "prod"}]},
            {"InstanceId": "i-deadbeef02",
             "InstanceType": "m5.large",
             "State": {"Name": "stopped"},
             "Placement": {"AvailabilityZone": "us-east-1b"},
             "PrivateIpAddress": "10.0.1.99",
             "PlatformDetails": "Windows",
             "LaunchTime": "2026-02-01T08:00:00.000Z",
             "Tags": [{"Key": "Name", "Value": "win-app-02"}]},
        ]
    }]
})


_AZURE_JSON = json.dumps([
    {"vmId": "vm-uuid-1", "name": "vm-prod-01",
     "location": "eastus2", "powerState": "VM running",
     "hardwareProfile": {"vmSize": "Standard_D4s_v5"},
     "publicIps": "20.30.40.50", "privateIps": "10.5.0.4",
     "storageProfile": {"osDisk": {"osType": "Linux"}},
     "tags": {"env": "prod"},
     "timeCreated": "2026-03-01T10:00:00Z"},
    {"vmId": "vm-uuid-2", "name": "vm-stg-02",
     "location": "westus", "powerState": "VM deallocated",
     "hardwareProfile": {"vmSize": "Standard_B2s"},
     "privateIps": "10.6.0.5",
     "storageProfile": {"osDisk": {"osType": "Windows"}},
     "tags": {"env": "stg"},
     "timeCreated": "2026-03-15T10:00:00Z"},
])


_GCP_JSON = json.dumps([
    {"id": "1234567890", "name": "gce-prod-01",
     "zone": "projects/p/zones/us-central1-a",
     "status": "RUNNING",
     "machineType": "projects/p/zones/us-central1-a/machineTypes/n2-standard-4",
     "networkInterfaces": [{
         "networkIP": "10.10.0.4",
         "accessConfigs": [{"natIP": "34.10.20.30"}],
     }],
     "labels": {"os": "linux", "env": "prod"},
     "creationTimestamp": "2026-04-01T10:00:00.000-07:00"},
])


# ============================================================== AWS

def test_parse_aws_extracts_instances():
    items = parse_aws_describe_instances(_AWS_JSON)
    assert len(items) == 2
    web = next(i for i in items if i.name == "web-prod-01")
    assert web.public_ip == "54.10.20.30"
    assert web.private_ip == "10.0.1.42"
    assert web.region == "us-east-1"
    assert web.state == "running"
    assert web.tags["env"] == "prod"


def test_harvest_aws_with_json_text_no_cli():
    r = harvest_aws(json_text=_AWS_JSON)
    assert r.cloud == "aws"
    assert r.count == 2
    assert not r.error


def test_harvest_aws_records_runner_failure():
    def boom(cmd): raise RuntimeError("creds expired")
    r = harvest_aws(run_fn=boom)
    assert "creds expired" in r.error


# ============================================================== Azure

def test_parse_az_vm_list_handles_state():
    items = parse_az_vm_list(_AZURE_JSON)
    assert len(items) == 2
    by_name = {i.name: i for i in items}
    assert by_name["vm-prod-01"].state == "running"
    assert by_name["vm-stg-02"].state == "deallocated"
    assert by_name["vm-prod-01"].os == "linux"


def test_harvest_azure_with_json_text():
    r = harvest_azure(json_text=_AZURE_JSON)
    assert r.cloud == "azure"
    assert r.count == 2


# ============================================================== GCP

def test_parse_gcloud_extracts_ips_from_nested_interfaces():
    items = parse_gcloud_list(_GCP_JSON)
    assert len(items) == 1
    g = items[0]
    assert g.public_ip == "34.10.20.30"
    assert g.private_ip == "10.10.0.4"
    assert g.state == "running"
    assert g.instance_type == "n2-standard-4"


def test_harvest_gcp_with_json_text():
    r = harvest_gcp(json_text=_GCP_JSON)
    assert r.cloud == "gcp"
    assert r.count == 1


# ============================================================ unified

def test_instances_as_discovered_hosts_handles_all_three():
    aws = harvest_aws(json_text=_AWS_JSON)
    az = harvest_azure(json_text=_AZURE_JSON)
    gcp = harvest_gcp(json_text=_GCP_JSON)
    aws_hosts = instances_as_discovered_hosts(aws)
    az_hosts = instances_as_discovered_hosts(az)
    gcp_hosts = instances_as_discovered_hosts(gcp)

    required = {"ip", "hostname", "mac", "vendor_guess",
                "device_type_guess", "open_ports", "banners"}
    for h in aws_hosts + az_hosts + gcp_hosts:
        assert required <= set(h.keys())
        assert h["device_type_guess"] == "server"
    # AWS public_ip should populate ip field
    web = next(h for h in aws_hosts if h["hostname"] == "web-prod-01")
    assert web["ip"] == "54.10.20.30"
    # GCP linux instance should map os_guess=linux
    g = gcp_hosts[0]
    assert g["os_guess"] == "linux"


def test_parse_handles_invalid_json():
    """Returns [] gracefully, doesn't raise."""
    assert parse_aws_describe_instances("not json") == []
    assert parse_az_vm_list("") == []
    assert parse_gcloud_list("{bad") == []
