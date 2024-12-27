#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: warpgate_target_info
short_description: Get information about Warpgate targets
description:
    - Retrieve information about one or more Warpgate targets
    - Returns detailed configuration for SSH, HTTP, MySQL, and Postgres targets
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
            - Name of the target to retrieve
            - If not specified, returns information about all targets
        required: false
        type: str
    search:
        description:
            - Search string to filter targets
            - If specified, only returns targets matching the search string
        required: false
        type: str
    cache_time:
        description:
            - Time in seconds to cache the results
            - Default is 300 seconds (5 minutes)
            - Set to 0 to disable caching
        type: int
        default: 300
'''

EXAMPLES = '''
# Get information about all targets
- name: Get all targets
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"

# Get information about a specific target
- name: Get specific target
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    name: "prod-server"

# Search for targets matching a pattern
- name: Search targets
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    search: "prod-"
    
# Get targets with custom cache time
- name: Get targets with 1 hour cache
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    cache_time: 3600

# Get targets with no caching
- name: Get targets without cache
  warpgate_target_info:
    url: "http://localhost:8888/@warpgate/admin/api"
    admin_username: "admin"
    admin_password: "adminpass"
    cache_time: 0
'''

RETURN = '''
targets:
    description: List of target information
    type: list
    returned: always
    contains:
        id:
            description: Target UUID
            type: str
            returned: always
        name:
            description: Target name
            type: str
            returned: always
        kind:
            description: Type of target (Http, MySql, Ssh, Postgres, WebAdmin)
            type: str
            returned: always
        allow_roles:
            description: List of roles allowed to access this target
            type: list
            returned: always
        options:
            description: Target configuration options
            type: dict
            returned: always
        roles:
            description: List of roles associated with the target
            type: list
            returned: always
            contains:
                id:
                    description: Role UUID
                    type: str
                    returned: always
                name:
                    description: Role name
                    type: str
                    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
import json
import time
import hashlib

class WarpgateClient:
    def __init__(self, module):
        self.module = module
        self.base_url = module.params['url'].rstrip('/')
        self.auth_base_url = self.base_url.rsplit('/@warpgate/admin/api', 1)[0] + '/@warpgate/api'
        self.cookies = None
        self.cache_key_prefix = hashlib.sha256(self.base_url.encode()).hexdigest()[:8]

    def _log(self, msg):
        """Helper method to handle debug logging"""
        if self.module._debug:
            self.module.warn(msg)

    def _get_cache_key(self, name=None, search=None):
        """Generate a unique cache key based on query parameters"""
        key_parts = [self.cache_key_prefix]
        if name:
            key_parts.append(f"name={name}")
        if search:
            key_parts.append(f"search={search}")
        return "_".join(key_parts)

    def _get_cached_data(self, cache_key):
        """Retrieve data from cache if valid"""
        if not self.module.params['cache_time']:
            return None

        try:
            cached_data = self.module.cache.get(cache_key)
            if cached_data:
                cached_time = cached_data.get('cached_time', 0)
                if time.time() - cached_time < self.module.params['cache_time']:
                    self._log(f"[DEBUG] Cache hit for key: {cache_key}")
                    return cached_data.get('data')
            self._log(f"[DEBUG] Cache miss for key: {cache_key}")
        except Exception as e:
            self._log(f"Cache retrieval error (non-fatal): {str(e)}")
        return None

    def _set_cached_data(self, cache_key, data):
        """Store data in cache with timestamp"""
        if not self.module.params['cache_time']:
            return

        try:
            cache_data = {
                'cached_time': time.time(),
                'data': data
            }
            self.module.cache.set(cache_key, cache_data)
            self._log(f"[DEBUG] Updated cache for key: {cache_key}")
        except Exception as e:
            self._log(f"Cache storage error (non-fatal): {str(e)}")

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
                
            self._log(f"[DEBUG] Authentication successful")
            
        except Exception as e:
            self.module.fail_json(msg=f"Authentication error: {str(e)}")

    def _send_request(self, method, path, data=None, params=None):
        """Send request to the Warpgate API with authentication handling"""
        if self.cookies is None:
            self.authenticate()

        url = f"{self.base_url}{path}"
        if params:
            param_str = '&'.join(f"{k}={v}" for k, v in params.items() if v is not None)
            url = f"{url}?{param_str}"
            
        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.cookies
        }
        
        try:
            encoded_data = json.dumps(data).encode('utf-8') if data else None
            self._log(f"[DEBUG] Sending {method} request to {url}")
            
            response, info = fetch_url(
                self.module,
                url,
                method=method,
                data=encoded_data,
                headers=headers
            )
            
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
            self._log(f"[DEBUG] Response status code: {status_code}")
            
            if response:
                content = response.read()
                if content:
                    try:
                        decoded = content.decode('utf-8')
                        self._log(f"[DEBUG] Response content: {decoded}")
                        return json.loads(decoded), status_code
                    except json.JSONDecodeError as e:
                        self.module.fail_json(msg=f"Failed to decode JSON response: {str(e)}")
            return None, status_code
            
        except Exception as e:
            self.module.fail_json(msg=f"Request error: {str(e)}")

    def get_targets(self, search=None):
        """Get all targets or search for specific ones with caching"""
        cache_key = self._get_cache_key(search=search)
        cached_data = self._get_cached_data(cache_key)
        
        if cached_data is not None:
            return cached_data

        params = {'search': search} if search else None
        response, status_code = self._send_request('GET', '/targets', params=params)
        
        if status_code != 200:
            self.module.fail_json(msg=f"Failed to get targets: status code {status_code}")
        
        self._set_cached_data(cache_key, response)
        return response

    def get_target_roles(self, target_id):
        """Get roles associated with a target with caching"""
        cache_key = self._get_cache_key(f"roles_for_{target_id}")
        cached_data = self._get_cached_data(cache_key)
        
        if cached_data is not None:
            return cached_data

        response, status_code = self._send_request('GET', f'/targets/{target_id}/roles')
        
        if status_code == 200:
            self._set_cached_data(cache_key, response)
            return response
        elif status_code == 404:
            self._set_cached_data(cache_key, [])
            return []
        else:
            self.module.fail_json(msg=f"Failed to get target roles: status code {status_code}")

def format_target_info(target, roles):
    """Format target information for output"""
    info = {
        'id': target['id'],
        'name': target['name'],
        'kind': target['options']['kind'],
        'allow_roles': target['allow_roles'],
        'options': target['options']
    }
    
    if roles:
        info['roles'] = [{'id': role['id'], 'name': role['name']} for role in roles]
        
    return info

def main():
    module_args = dict(
        url=dict(type='str', required=True),
        admin_username=dict(type='str', required=True),
        admin_password=dict(type='str', required=True, no_log=True),
        name=dict(type='str', required=False),
        search=dict(type='str', required=False),
        cache_time=dict(type='int', default=300),
        _ansible_debug=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        targets=[]
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        mutually_exclusive=[['name', 'search']]
    )

    client = WarpgateClient(module)
    
    try:
        # Get all targets first
        all_targets = client.get_targets(module.params['search'])
        
        # Filter for specific target if name is provided
        targets_to_process = []
        if module.params['name']:
            for target in all_targets:
                if target['name'] == module.params['name']:
                    targets_to_process = [target]
                    break
            if not targets_to_process:
                module.fail_json(msg=f"Target '{module.params['name']}' not found")
        else:
            targets_to_process = all_targets

        # Get roles for each target and format output
        for target in targets_to_process:
            roles = client.get_target_roles(target['id'])
            result['targets'].append(format_target_info(target, roles))

        module.exit_json(**result)
        
    except Exception as e:
        module.fail_json(msg=f"Error: {str(e)}")

if __name__ == '__main__':
    main()