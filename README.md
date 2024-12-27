⚠️EXTREMELY ALPHA -- USE AT YOUR OWN RISK⚠️ 

# Warpgate Ansible Module

This Ansible module allows you to manage Warpgate targets, including creating, updating, and deleting SSH, HTTP, MySQL, and Postgres targets.

## Installation

1. Ensure you have Ansible installed on your system.
2. Copy the `warpgate_target.py`, `warpgate_target_info.py` files to your Ansible module directory (I use `$(PWD)/./library`).

## Module Overview

This collection includes two main modules:

1. `warpgate_target`: Manage Warpgate targets (create, update, delete)
2. `warpgate_target_info`: Retrieve information about Warpgate targets

## Usage

### warpgate_target

This module is used to create, update, or delete Warpgate targets.

#### Parameters

- `url`: URL of the Warpgate admin API (required)
- `admin_username`: Username for Warpgate admin authentication (required)
- `admin_password`: Password for Warpgate admin authentication (required)
- `name`: Name of the target (required)
- `state`: Whether the target should exist or not (choices: absent, present; default: present)
- `kind`: Type of target (choices: Http, MySql, Ssh, Postgres, WebAdmin; required)
- `host`: Target host address
- `port`: Target port
- `username`: Username for target authentication
- `password`: Password for target authentication
- `tls_mode`: TLS mode (choices: Disabled, Preferred, Required; default: Required)
- `tls_verify`: Whether to verify TLS certificates (default: true)
- `roles`: List of role names to assign to the target

#### Example

```yaml
- name: Create SSH target
  warpgate_target:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    name: "prod-server"
    kind: "Ssh"
    state: present
    host: "prod.example.com"
    port: 22
    username: "admin"
    password: "secret" # Omit for pubkey
    roles:
        - "warpgate:admin"
        - "codytestrole"
```

### warpgate_target_info

This module is used to retrieve information about Warpgate targets.

#### Parameters

- `url`: URL of the Warpgate admin API (required)
- `admin_username`: Username for Warpgate admin authentication (required)
- `admin_password`: Password for Warpgate admin authentication (required)
- `name`: Name of the target to retrieve (optional)
- `search`: Search string to filter targets (optional)

#### Example

```yaml
- name: Get all targets
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"

- name: Get specific target
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    name: "prod-server"
```

``` shell
TASK [Show target info1] ********************************************************************
ok: [localhost] => {
    "target_info1.targets": [
        {
            "allow_roles": [],
            "id": "68b5f2c7-91f1-4b7f-967c-e3477164e0f5",
            "kind": "Ssh",
            "name": "warpgate-vm-3.hawkinternal.com-ansible",
            "options": {
                "allow_insecure_algos": null,
                "auth": {
                    "kind": "PublicKey"
                },
                "host": "141.193.23.87",
                "kind": "Ssh",
                "port": 22,
                "username": "root"
            },
            "roles": [
                {
                    "id": "f67aec4f-2623-4de3-9129-8d2542f0804a",
                    "name": "warpgate:admin"
                }
            ]
        }
    ]
}
```

## Return Values

The modules return information about the targets, including:

- `id`: Target UUID
- `name`: Target name
- `kind`: Type of target
- `allow_roles`: List of roles allowed to access this target
- `options`: Target configuration options
- `roles`: List of roles associated with the target

## License

Apache-2.0 license
