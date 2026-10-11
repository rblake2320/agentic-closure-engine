"""Read the actual self-hosted service boundaries without exposing keys or credentials."""

import argparse
import json
import subprocess
from pathlib import Path

ROLES = ("actor", "owner", "authority", "verifier", "broker", "custody", "gateway")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default="agentic-closure-engine")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    observations = []
    for service in ROLES:
        name = f"{args.project}-{service}-1"
        metadata = json.loads(subprocess.check_output(["docker", "inspect", name], text=True))[0]
        root = "custodian" if service == "custody" else service
        foreign_roles = [
            r for r in ("actor", "owner", "authority", "verifier", "broker", "custodian") if r != root
        ]
        code = f"""import json,os
from pathlib import Path
root=Path('/state/{root}')
own_key=root/'identity.key'
result={{'uid':os.getuid(),'own_key_available':own_key.is_file()}}
foreign_roles={foreign_roles!r}
result['foreign_keys_absent']=all(not Path('/state/'+r+'/identity.key').exists() for r in foreign_roles)
result['docker_socket_absent']=not Path('/var/run/docker.sock').exists()
result['broker_credential_absent']=({service!r} == 'broker' or not Path('/state/broker/targets').exists())
checks=[('rootfs_write_denied',Path('/app/boundary-probe')),
        ('package_write_denied',Path('/usr/local/lib/python3.13/site-packages/closure_engine/boundary-probe'))]
for label,path in checks:
    try:
        path.write_text('boundary check')
        path.unlink()
        result[label]=False
    except OSError:
        result[label]=True
if own_key.is_file() and {service!r} != 'custody':
    try:
        p=root/'boundary-probe';p.write_text('boundary check');p.unlink()
        result['key_directory_write_denied']=False
    except OSError:
        result['key_directory_write_denied']=True
print(json.dumps(result))
"""
        result = json.loads(
            subprocess.check_output(["docker", "exec", name, "python", "-I", "-c", code], text=True)
        )
        result["service"] = service
        result["image"] = metadata["Image"]
        result["readonly_rootfs"] = metadata["HostConfig"]["ReadonlyRootfs"]
        result["capabilities_dropped"] = metadata["HostConfig"]["CapDrop"]
        result["mounts"] = [
            {"destination": m["Destination"], "writable": m["RW"]} for m in metadata["Mounts"]
        ]
        assert result["uid"] != 0, result
        assert result["own_key_available"] == (service != "gateway"), result
        assert all(
            result[k]
            for k in (
                "foreign_keys_absent",
                "docker_socket_absent",
                "rootfs_write_denied",
                "package_write_denied",
                "readonly_rootfs",
            )
        ), result
        if service not in {"custody", "gateway"}:
            assert result["key_directory_write_denied"], result
        if service != "broker":
            assert result["broker_credential_absent"], result
        observations.append(result)
    receipt = {
        "result": "Worked",
        "services": observations,
        "scope": "Actual running containers, installed package, mount/UID/read/write boundaries",
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps({"result": "Worked", "services": len(observations), "receipt": args.output}))


if __name__ == "__main__":
    main()
