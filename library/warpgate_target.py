#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
import json

DOCUMENTATION = '''
---
module: warpgate_target
short_description: Manage Warpgate targets
description:
    - Create, update, delete and manage targets in Warpgate
    - Supports SSH, HTTP, MySQL, and Postgres targets
    - Manage target roles and access permissions
options:
    url:
        description:
            - URL of the Warpgate admin API
        required: true
        type: str
    admin_username:
        description:
            - Username for Warpgate admin authentication
        required: true
        type: str
    admin_password:
        description:
            - Password for Warpgate admin authentication
        required: true
        type: str
        no_log: true
    name:
        description:
            - Name of the target
        required: true
        type: str
    state:
        description:
            - Whether the target should exist or not
        choices: [ absent, present ]
        default: present
        type: str
    kind:
        description:
            - Type of target
        choices: [ Http, MySql, Ssh, Postgres, WebAdmin ]
        required: true
        type: str
    host:
        description:
            - Target host address
        type: str
    port:
        description:
            - Target port
        type: int
    username:
        description:
            - Username for target authentication
        type: str
    password:
        description:
            - Password for target authentication
        type: str
        no_log: true
    tls_mode:
        description:
            - TLS mode for the connection
        choices: [ Disabled, Preferred, Required ]
        default: Required
        type: str
    tls_verify:
        description:
            - Whether to verify TLS certificates
        type: bool
        default: true
    roles:
        description:
            - List of role names to assign to the target
            - If specified, these roles will be the only roles assigned to the target
            - Existing roles not in this list will be removed
        type: list
        elements: str
        required: false
'''

EXAMPLES = '''
- name: Create SSH target with roles
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
    password: "secret"
    roles:
      - "admin"
      - "developer"

- name: Update target roles
  warpgate_target:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    name: "prod-server"
    kind: "Ssh"
    state: present
    roles:
      - "developer"
'''

RETURN = '''
target:
    description: Target information
    type: dict
    returned: success
    contains:
        id:
            description: Target UUID
            type: str
        name:
            description: Target name
            type: str
        options:
            description: Target configuration options
            type: dict
        roles:
            description: List of roles assigned to the target
            type: list
            elements: dict
            contains:
                id:
                    description: Role UUID
                    type: str
                name:
                    description: Role name
                    type: str
'''

class WarpgateClient:
    def __init__(self, module):
        self.module = module
        self.base_url = module.params['url'].rstrip('/')
        self.auth_base_url = self.base_url.rsplit('/@warpgate/admin/api', 1)[0] + '/@warpgate/api'
        self.cookies = None

    def _log(self, msg):
        """Helper method to handle debug logging"""
        if self.module._debug:
            self.module.warn(msg)

    def authenticate(self):
        """Authenticate with the Warpgate API"""
        auth_data = {
            'username': self.module.params['admin_username'],
            'password': self.module.params['admin_password']
        }

        url = f"{self.auth_base_url}/auth/login"
        headers = {'Content-Type': 'application/json'}

        try:
            data = json.dumps(auth_data).encode('utf-8')
            self._log(f"[DEBUG] Sending authentication request to {url}")

            response, info = fetch_url(
                self.module,
                url,
                method='POST',
                data=data,
                headers=headers
            )

            self._log(f"[DEBUG] Authentication response info: {info}")

            if info['status'] == -1:
                self.module.fail_json(msg=f"Failed to connect to Warpgate: {info['msg']}")
            elif info['status'] == 401:
                self.module.fail_json(msg="Authentication failed: Invalid credentials")
            elif info['status'] != 201:
                self.module.fail_json(msg=f"Authentication failed with status code: {info['status']}")

            if 'set-cookie' in info:
                self.cookies = info['set-cookie']
            elif 'cookies_string' in info:
                self.cookies = info['cookies_string']
            else:
                self.module.fail_json(msg="No cookie received in authentication response")

            self._log(f"[DEBUG] Authentication successful, received cookie: {self.cookies}")

        except Exception as e:
            self.module.fail_json(msg=f"Authentication error: {str(e)}")

    def _send_request(self, method, path, data=None):
        if self.cookies is None:
            self.authenticate()

        url = f"{self.base_url}{path}"
        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.cookies
        }

        try:
            encoded_data = json.dumps(data).encode('utf-8') if data else None
            self._log(f"[DEBUG] Sending {method} request to {url}")
            if data:
                self._log(f"[DEBUG] Request data: {json.dumps(data, indent=2)}")

            response, info = fetch_url(
                self.module,
                url,
                method=method,
                data=encoded_data,
                headers=headers
            )

            self._log(f"[DEBUG] Response info: {info}")

            if info['status'] == 401:
                self._log("[DEBUG] Got 401, attempting to re-authenticate")
                self.authenticate()
                headers['Cookie'] = self.cookies
                response, info = fetch_url(
                    self.module,
                    url,
                    method=method,
                    data=encoded_data,
                    headers=headers
                )

            status_code = info['status']
            self._log(f"[DEBUG] Final status code: {status_code}")

            if response:
                content = response.read()
                if content:
                    try:
                        decoded = content.decode('utf-8')
                        self._log(f"[DEBUG] Response content: {decoded}")
                        return json.loads(decoded), status_code
                    except json.JSONDecodeError as e:
                        self._log(f"[DEBUG] JSON decode error: {str(e)}")
                        self.module.fail_json(msg=f"Failed to decode JSON response: {content}, Error: {str(e)}")
            return None, status_code

        except Exception as e:
            self.module.fail_json(msg=f"Request error: {str(e)}")

    def get_target(self, name):
        """Get target by name"""
        response, status_code = self._send_request('GET', '/targets')
        if status_code == 200:
            targets = response
            for target in targets:
                if target['name'] == name:
                    return target
        return None

    def get_all_roles(self):
        """Get all available roles"""
        response, status_code = self._send_request('GET', '/roles')
        if status_code != 200:
            self.module.fail_json(msg=f"Failed to get roles: status code {status_code}")
        return response

    def get_target_roles(self, target_id):
        """Get roles associated with a target"""
        response, status_code = self._send_request('GET', f'/targets/{target_id}/roles')
        if status_code == 200:
            return response
        elif status_code == 404:
            return []
        else:
            self.module.fail_json(msg=f"Failed to get target roles: status code {status_code}")

    def add_role_to_target(self, target_id, role_id):
        """Add a role to a target"""
        _, status_code = self._send_request('POST', f'/targets/{target_id}/roles/{role_id}')
        if status_code not in [201, 409]:  # 409 means role is already assigned
            self.module.fail_json(msg=f"Failed to add role to target: status code {status_code}")
        return status_code == 201

    def remove_role_from_target(self, target_id, role_id):
        """Remove a role from a target"""
        _, status_code = self._send_request('DELETE', f'/targets/{target_id}/roles/{role_id}')
        if status_code not in [204, 404]:  # 404 means role was already removed
            self.module.fail_json(msg=f"Failed to remove role from target: status code {status_code}")
        return status_code == 204

    def create_target(self, params):
        """Create a new target"""
        options = self._build_target_options(params)
        data = {
            'name': params['name'],
            'options': options
        }

        response, status_code = self._send_request('POST', '/targets', data)

        if status_code == 201:
            return response
        elif status_code == 400:
            error_msg = response if response else "Unknown error"
            self.module.fail_json(msg=f"Failed to create target. Server response: {error_msg}")
        else:
            self.module.fail_json(msg=f"Failed to create target. Unexpected status code: {status_code}")

    def _compare_target_states(self, existing_target, desired_params):
        """Compare existing target state with desired state"""
        if existing_target['name'] != desired_params['name']:
            self._log("[DEBUG] Name changed")
            return True

        existing_options = existing_target['options']
        desired_options = self._build_target_options(desired_params)

        # Compare basic fields
        if existing_options['kind'] != desired_options['kind']:
            self._log("[DEBUG] Kind changed")
            return True

        kind = desired_options['kind']

        if kind in ['Ssh', 'MySql', 'Postgres']:
            # Compare host, port, username
            for field in ['host', 'port', 'username']:
                if existing_options.get(field) != desired_options.get(field):
                    self._log(f"[DEBUG] Field {field} changed")
                    return True

            # Compare auth/password
            if kind == 'Ssh':
                existing_auth = existing_options.get('auth', {})
                desired_auth = desired_options.get('auth', {})

                if existing_auth.get('kind') != desired_auth.get('kind'):
                    self._log("[DEBUG] SSH auth kind changed")
                    return True

                # Only compare password if we're using password auth
                if desired_auth.get('kind') == 'Password' and 'password' in desired_auth:
                    self._log("[DEBUG] SSH password provided")
                    return True
            else:
                # For MySQL/Postgres, if password is provided, consider it a change
                if 'password' in desired_options:
                    self._log("[DEBUG] Database password provided")
                    return True

            # Compare TLS settings for MySQL/Postgres
            if kind in ['MySql', 'Postgres']:
                existing_tls = existing_options.get('tls', {})
                desired_tls = desired_options.get('tls', {})

                if (existing_tls.get('mode') != desired_tls.get('mode') or
                    existing_tls.get('verify') != desired_tls.get('verify')):
                    self._log("[DEBUG] TLS settings changed")
                    return True

        elif kind == 'Http':
            # Compare URL and TLS settings
            if existing_options.get('url') != desired_options.get('url'):
                self._log("[DEBUG] HTTP URL changed")
                return True

            existing_tls = existing_options.get('tls', {})
            desired_tls = desired_options.get('tls', {})

            if (existing_tls.get('mode') != desired_tls.get('mode') or
                existing_tls.get('verify') != desired_tls.get('verify')):
                self._log("[DEBUG] HTTP TLS settings changed")
                return True

        self._log("[DEBUG] No changes detected")
        return False

    def update_target(self, target_id, params):
        """Update target if changes are needed"""
        existing_target = self.get_target(params['name'])
        if not self._compare_target_states(existing_target, params):
            return existing_target  # No changes needed

        options = self._build_target_options(params)
        data = {
            'name': params['name'],
            'options': options
        }

        response, status_code = self._send_request('PUT', f'/targets/{target_id}', data)
        if status_code == 200:
            return response
        else:
            self.module.fail_json(msg=f"Failed to update target: status code {status_code}")

    def delete_target(self, target_id):
        """Delete a target"""
        _, status_code = self._send_request('DELETE', f'/targets/{target_id}')
        return status_code in [204, 404]

    def _build_target_options(self, params):
        """Build target options based on target kind"""
        kind = params['kind']
        options = {'kind': kind}

        if kind in ['Ssh', 'MySql', 'Postgres']:
            required_params = ['host', 'port', 'username']
            for param in required_params:
                if not params.get(param):
                    self.module.fail_json(msg=f"Parameter '{param}' is required for {kind} target")

            options.update({
                'host': params['host'],
                'port': params['port'],
                'username': params['username']
            })

            if params.get('password'):
                if kind == 'Ssh':
                    options['auth'] = {
                        'kind': 'Password',
                        'password': params['password']
                    }
                else:
                    options['password'] = params['password']
            elif kind == 'Ssh':
                options['auth'] = {
                    'kind': 'PublicKey'
                }

            if kind in ['MySql', 'Postgres']:
                options['tls'] = {
                    'mode': params.get('tls_mode', 'Required'),
                    'verify': params.get('tls_verify', True)
                }

        elif kind == 'Http':
            if not params.get('url'):
                self.module.fail_json(msg="Parameter 'url' is required for Http target")

            options.update({
                'url': params['url'],
                'tls': {
                    'mode': params.get('tls_mode', 'Required'),
                    'verify': params.get('tls_verify', True)
                }
            })

        return options

    def sync_target_roles(self, target_id, desired_roles):
        """Synchronize target roles with desired state"""
        if not desired_roles:
            return False, []

        changed = False
        all_roles = self.get_all_roles()
        role_map = {role['name']: role['id'] for role in all_roles}

        # Validate desired roles exist
        invalid_roles = [role for role in desired_roles if role not in role_map]
        if invalid_roles:
            self.module.fail_json(msg=f"Invalid roles specified: {', '.join(invalid_roles)}")

        # Get current roles
        current_roles = self.get_target_roles(target_id)
        current_role_names = {role['name'] for role in current_roles}

        # Add missing roles
        for role_name in desired_roles:
            if role_name not in current_role_names:
                if self.add_role_to_target(target_id, role_map[role_name]):
                    changed = True

        # Remove extra roles
        for role in current_roles:
            if role['name'] not in desired_roles:
                if self.remove_role_from_target(target_id, role['id']):
                    changed = True

        # Get updated roles if changes were made
        return changed, self.get_target_roles(target_id) if changed else current_roles

def main():
    module_args = dict(
        url=dict(type='str', required=True),
        admin_username=dict(type='str', required=True),
        admin_password=dict(type='str', required=True, no_log=True),
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        kind=dict(type='str', required=True, choices=['Http', 'MySql', 'Ssh', 'Postgres', 'WebAdmin']),
        host=dict(type='str'),
        port=dict(type='int'),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
        tls_mode=dict(type='str', default='Required', choices=['Disabled', 'Preferred', 'Required']),
        tls_verify=dict(type='bool', default=True),
        roles=dict(type='list', elements='str', required=False),
        _ansible_debug=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        target=None,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    client = WarpgateClient(module)

    try:
        module.log("[DEBUG] Starting target check")
        existing_target = client.get_target(module.params['name'])

        if module.params['state'] == 'absent':
            if existing_target:
                if not module.check_mode:
                    if client.delete_target(existing_target['id']):
                        result['changed'] = True
                else:
                    result['changed'] = True
            module.exit_json(**result)

        target_changed = False
        roles_changed = False
        target = None

        if not existing_target:
            if not module.check_mode:
                target = client.create_target(module.params)
                target_changed = True
            else:
                target_changed = True
                target = {'name': module.params['name'], 'id': 'check_mode_id'}
        else:
            # Update target if needed
            if not module.check_mode:
                target = client.update_target(existing_target['id'], module.params)
                target_changed = (target != existing_target)
            else:
                target_changed = client._compare_target_states(existing_target, module.params)
                target = existing_target

        # Handle role management if target exists or we're creating one
        if target and module.params.get('roles') is not None:
            if not module.check_mode:
                roles_changed, roles = client.sync_target_roles(target['id'], module.params['roles'])
                target['roles'] = roles
            else:
                # In check mode, simulate role changes
                current_roles = client.get_target_roles(target['id']) if existing_target else []
                current_role_names = {role['name'] for role in current_roles}
                desired_roles = set(module.params['roles'])
                roles_changed = (current_role_names != desired_roles)
                target['roles'] = [{'name': name, 'id': 'check_mode_id'} for name in desired_roles]

        result['changed'] = target_changed or roles_changed
        result['target'] = target

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=f"Error: {str(e)}")

if __name__ == '__main__':
    main()
