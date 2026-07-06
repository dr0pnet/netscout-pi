import os
import subprocess


def get_external_storage():
    try:
        output = subprocess.check_output(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,LABEL,FSTYPE"],
            text=True
        )

        import json
        data = json.loads(output)

        drives = []

        for dev in data.get("blockdevices", []):
            for part in dev.get("children", []) or []:
                mount = part.get("mountpoint")

                if mount and (
                    mount.startswith("/media/")
                    or mount.startswith("/mnt/")
                    or mount.startswith("/run/media/")
                ):
                    drives.append({
                        "name": part.get("name"),
                        "label": part.get("label") or part.get("name"),
                        "size": part.get("size"),
                        "fstype": part.get("fstype"),
                        "mountpoint": mount
                    })

        return drives

    except Exception:
        return []


def get_storage_path():
    drives = get_external_storage()

    if drives:
        path = os.path.join(drives[0]["mountpoint"], "netscout")
        os.makedirs(path, exist_ok=True)
        return path

    fallback = os.path.expanduser("~/netscout-storage")
    os.makedirs(fallback, exist_ok=True)
    return fallback
