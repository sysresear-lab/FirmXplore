"""Bounded functional checks of TP-Link guests through container loopback.

Passwords, keys, cookies, session IDs and decrypted page contents remain in
memory. Evidence contains application assertions, lengths and hashes only.
This module implements the protocols in the supplied firmware's own login JS.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import secrets
import subprocess
import time


def aes(data, key, iv, *, decrypt=False):
    command = ['/usr/bin/openssl', 'enc', '-aes-128-cbc', '-K', key.hex(), '-iv', iv.hex()]
    if decrypt:
        command.append('-d')
    result = subprocess.run(command, input=data, capture_output=True, timeout=3)
    if result.returncode:
        raise ValueError('AES transformation failed')
    return result.stdout


def rsa_chunks(text, nn, ee):
    modulus, exponent = int(nn, 16), int(ee, 16)
    width = (modulus.bit_length() + 7)//8
    if width != 64 or exponent not in (3, 65537):
        raise ValueError('unexpected vendor RSA parameters')
    data, chunks = text.encode('ascii'), []
    for offset in range(0, len(data), width-11):
        part = data[offset:offset+width-11]
        padding = bytes(secrets.randbelow(255)+1 for _ in range(width-len(part)-3))
        block = b'\x00\x02'+padding+b'\x00'+part
        value = pow(int.from_bytes(block, 'big'), exponent, modulus)
        chunks.append(value.to_bytes(width, 'big').hex())
    return ''.join(chunks)


class VendorEncryption:
    def __init__(self, nn, ee, seq, password):
        self.nn, self.ee, self.seq = nn, ee, int(seq)
        self.key = ''.join(str(secrets.randbelow(10)) for _ in range(16)).encode()
        self.iv = ''.join(str(secrets.randbelow(10)) for _ in range(16)).encode()
        self.password_hash = hashlib.md5(('admin'+password).encode()).hexdigest()

    def encrypt(self, data, *, login=False):
        encrypted = base64.b64encode(aes(data.encode(), self.key, self.iv)).decode()
        signature = f'h={self.password_hash}&s={self.seq+len(encrypted)}'
        if login:
            signature = f'key={self.key.decode()}&iv={self.iv.decode()}&'+signature
        return {'sign': rsa_chunks(signature, self.nn, self.ee), 'data': encrypted}

    def decrypt(self, data):
        return aes(base64.b64decode(data), self.key, self.iv, decrypt=True).decode('utf-8', 'replace')


class GuestClient:
    """A fixed loopback destination and finite request/response budgets."""
    def __init__(self, *, keep_alive=True):
        self.cookies = {}
        self.records = []
        self.request_count = 0
        self.referer = 'http://192.168.0.1/'
        self.connection = None
        self.keep_alive = keep_alive

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def request(self, path, body=None, *, record=True, label=None, content_type='text/plain', timeout=4):
        if not path.startswith('/') or path.startswith('//') or '\r' in path or '\n' in path:
            raise ValueError('invalid guest request path')
        self.request_count += 1
        if self.request_count > 48 or (body and len(body) > 16384):
            raise ValueError('functional request budget exceeded')
        headers = {'Host': '192.168.0.1', 'Referer': self.referer, 'Connection': 'keep-alive' if self.keep_alive else 'close'}
        if self.cookies:
            headers['Cookie'] = '; '.join(k+'='+v for k, v in self.cookies.items())
        if body is not None:
            headers['Content-Type'] = content_type
        self.last_label = label or path.split('?',1)[0]
        if self.connection is None:
            self.connection = http.client.HTTPConnection('127.0.0.1', 18080, timeout=timeout)
        connection = self.connection
        connection.timeout = timeout
        if getattr(connection,'sock',None):
            connection.sock.settimeout(timeout)
        start = time.monotonic()
        keep_alive = False
        try:
            connection.request('POST' if body is not None else 'GET', path, body, headers)
            response = connection.getresponse()
            keep_alive = self.keep_alive and not getattr(response,'will_close',True)
            self.last_response_framing = {'status':response.status,
                'content_length':response.getheader('Content-Length'),
                'transfer_encoding':response.getheader('Transfer-Encoding')}
            try:
                data = response.read(256*1024+1)
            except http.client.IncompleteRead as exc:
                self.last_response_framing.update(incomplete=True, received_bytes=len(exc.partial), expected_more=exc.expected)
                raise
            if len(data) > 256*1024:
                raise ValueError('guest response budget exceeded')
            for key, value in response.getheaders():
                if key.lower() == 'set-cookie':
                    pair = value.split(';', 1)[0].split('=', 1)
                    if len(pair) == 2:
                        self.cookies[pair[0]] = pair[1]
            info = {'label': label or path.split('?', 1)[0], 'method': 'POST' if body is not None else 'GET',
                    'status': response.status, 'bytes': len(data),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'content_type': response.getheader('Content-Type'),
                    'redirects_to_login': bool(re.search(r'(?:LoginRpm|login)\.htm',response.getheader('Location') or '',re.I)),
                    'duration_ms': round((time.monotonic()-start)*1000)}
            if record:
                self.records.append(info)
            return data.decode('utf-8', 'replace'), info
        finally:
            if not keep_alive:
                self.close()


STACK = '0,0,0,0,0,0'


def action(oid, attributes=(), kind=1):
    return f'[{oid}#{STACK}#{STACK}]0,{len(attributes)}\r\n'+''.join(x+'\r\n' for x in attributes)


def login_page(text):
    return 'pcPassword' in text or 'LoginRpm.htm' in text or 'login.htm' in text


def authentication_denied(text, info):
    # These legacy protected routes also return HTTP 200 with a short
    # JavaScript navigation to the landing page after logout.
    navigation = len(text) < 2048 and bool(re.search(r'(?:location\.href|(?:window|parent|top)\.location)\s*=',text))
    return info['status'] in (401,403) or info.get('redirects_to_login',False) or login_page(text) or navigation


def status_fields(text, encryption):
    """Require server-injected array assignments, not static variable uses."""
    parts = [text]
    decoded = 0
    for value in re.findall(r'\bvar\s+\w+\s*=\s*[\"\x27]([A-Za-z0-9+/=]{24,})[\"\x27]',text):
        try:
            parts.append(encryption.decrypt(value))
            decoded += 1
        except (ValueError, TypeError):
            continue
    names = sorted(set(re.findall(r'\b(statusPara|lanPara|wanPara|wlanPara)\s*=\s*(?:new\s+Array\s*\(|\[)', '\n'.join(parts))))
    return names, decoded


def wr841(client, password, checks):
    before, before_info = client.request('/main/status.htm', label='anonymous_status_before')
    checks['anonymous_status_denied'] = authentication_denied(before,before_info)
    first, _ = client.request('/cgi?1', action('MULTIMODE', ['webauth_first_login']))
    checks['first_login_required'] = bool(re.search(r'webauth_first_login=1\b', first))
    if checks['first_login_required']:
        checks['guest_configuration_change_attempted'] = True
        created, _ = client.request('/cgi?8', action('/cgi/auth', ['name=admin','oldPwd=admin','pwd='+password], 8), label='factory_onboarding', timeout=20)
        checks['password_created_via_vendor_api'] = '[error]0' in created and '$.ret=0' in created
    else:
        checks['blocked_reason'] = 'Existing credential required; no password guessing performed'
        return
    def perform_login(secret, label, *, expected_rejection=False):
        parameters, _ = client.request('/cgi?8', action('/cgi/getParm',kind=8),label=label+'_parameters')
        fields = {}
        for name in ('nn','ee','seq'):
            match = re.search(r'\b'+name+r'\s*=\s*[\"\x27]?([0-9a-fA-F]+)',parameters)
            if not match:
                raise ValueError('vendor login parameters unavailable')
            fields[name] = match[1]
        encryption = VendorEncryption(fields['nn'],fields['ee'],fields['seq'],secret)
        payload = encryption.encrypt('8\r\n'+action('/cgi/login',['username=admin','password='+secret],8),login=True)
        try:
            reply, _ = client.request('/cgi_gdpr',f"sign={payload['sign']}\r\ndata={payload['data']}\r\n",label=label)
        except (http.client.BadStatusLine,http.client.IncompleteRead) as exc:
            if not expected_rejection:
                raise
            checks['invalid_login_transport_error'] = type(exc).__name__
            client.close()
            return False, encryption
        plain = encryption.decrypt(reply.strip())
        return bool(re.search(r'\$\.ret=0\s*;',plain) and '[error]0' in plain), encryption
    checks['login_accepted'], encryption = perform_login(password,'encrypted_login')
    if not checks['login_accepted']:
        return
    checks['session_cookie_observed'] = bool(client.cookies.get('JSESSIONID')) and client.cookies.get('JSESSIONID') != 'deleted'
    client.referer = 'http://192.168.0.1/mainFrame.htm'
    page, _ = client.request('/main/status.htm', label='authenticated_status_page')
    checks['authenticated_status_page'] = 'IGD_DEV_INFO' in page or '$.act(ACT_GET,DEV_INFO' in page
    info, _ = client.request('/cgi?1', action('IGD_DEV_INFO',['modelName','description']),label='frontend_readonly_bootstrap')
    checks['frontend_bootstrap_observed'] = '[error]0' in info and 'modelName=' in info
    client.request('/cgi?8', action('/cgi/info',kind=8),label='frontend_session_bootstrap')
    def read_info(encryption,label):
        request = encryption.encrypt('1\r\n'+action('IGD_DEV_INFO',['modelName','softwareVersion','upTime']))
        answer, info = client.request('/cgi_gdpr',f"sign={request['sign']}\r\ndata={request['data']}\r\n",label=label)
        answer = encryption.decrypt(answer.strip())
        fields = sorted(set(re.findall(r'(?m)^(modelName|softwareVersion|upTime)=\S+',answer)))
        uptime = re.search(r'(?m)^upTime=(\d+)',answer)
        return {'status':info['status'],'handler_fields':fields,'uptime_seconds':int(uptime[1]) if uptime else None,
                'passed':'[error]0' in answer and fields==['modelName','softwareVersion','upTime']}
    initial = read_info(encryption,'authenticated_readonly_device_info')
    checks['readonly_handler_observed'] = initial['passed']
    checks['readonly_data_fields'] = initial['handler_fields']
    samples = []
    for index in range(10):
        samples.append(read_info(encryption,'authenticated_stability_sample'))
        if index != 9:
            time.sleep(3)
    uptimes = [x['uptime_seconds'] for x in samples]
    checks['authenticated_stability'] = {'samples':samples,'interval_seconds':3,
        'passed':all(x['passed'] for x in samples) and all(x is not None for x in uptimes) and uptimes==sorted(uptimes)}
    def logout(encryption,label):
        request = encryption.encrypt('8\r\n'+action('/cgi/logout',kind=8))
        client.request('/cgi_gdpr',f"sign={request['sign']}\r\ndata={request['data']}\r\n",label=label)
    logout(encryption,'logout')
    old, old_info = client.request('/main/status.htm',label='old_session_after_logout')
    checks['logout_revokes_session'] = authentication_denied(old,old_info)
    client.cookies.clear()
    client.close()
    accepted, _ = perform_login(password+'x','one_invalid_password',expected_rejection=True)
    denied, denied_info = client.request('/main/status.htm',label='protected_status_with_invalid_password')
    checks['invalid_password_rejected'] = not accepted and authentication_denied(denied,denied_info)
    checks['relogin_accepted'], encryption = perform_login(password,'known_password_relogin')
    if checks['relogin_accepted']:
        # The native frontend reloads its protected management frame after
        # every login; that request also establishes the runtime identity.
        client.request('/main/status.htm',label='management_frame_after_relogin')
        checks['status_after_relogin'] = read_info(encryption,'status_after_relogin')['passed']
        logout(encryption,'final_logout')


def wr940(client, password, checks):
    before, before_info = client.request('/userRpm/StatusRpm.htm', label='anonymous_status_before')
    checks['anonymous_status_denied'] = authentication_denied(before,before_info)
    initial, _ = client.request('/', label='onboarding_state')
    checks['first_login_required'] = bool(re.search(r'httpOriginalPwd\s*=\s*new Array\(\s*1\b',initial))
    if not checks['first_login_required']:
        checks['blocked_reason'] = 'Existing credential required; no password guessing performed'
        return
    def perform_login(secret, label):
        client.referer = 'http://192.168.0.1/'
        data, _ = client.request('/login/getRsa.json', '', label=label+'_parameters', content_type='application/json; charset=UTF-8')
        parameters = json.loads(data)
        encryption = VendorEncryption(parameters['rsa']['nn'], parameters['rsa']['mm'], parameters['seq'], secret)
        payload = encryption.encrypt(json.dumps({'name':'admin','password':secret},separators=(',',':')),login=True)
        reply, _ = client.request('/login/login.json','JSONDATA: '+json.dumps(payload,separators=(',',':'))+'\n',label=label, content_type='application/json; charset=UTF-8')
        login = json.loads(reply)
        if login.get('valid'):
            token = login.get('sessionId')
            login['_token_usable'] = isinstance(token,str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,128}',token))
            if login['_token_usable']:
                client.cookies['Authorization'] = str(parameters['seq'])
                client.referer = 'http://192.168.0.1/'+token+'/userRpm/Index.htm'
        return login, encryption
    checks['guest_configuration_change_attempted'] = True
    login, encryption = perform_login(password, 'factory_onboarding_and_login')
    checks['login_accepted'] = bool(login.get('valid') and login.get('_token_usable'))
    checks['password_created_via_vendor_api'] = checks['login_accepted']
    session = login.get('sessionId')
    if not checks['login_accepted']:
        return
    checks['session_token_observed'] = True
    page, _ = client.request('/'+session+'/userRpm/StatusRpm.htm',label='authenticated_status_page')
    names, decoded = status_fields(page,encryption)
    checks['authenticated_status_page'] = not login_page(page) and 'statusPara' in names
    checks['readonly_handler_observed'] = checks['authenticated_status_page'] and 'lanPara' in names
    checks['readonly_data_fields'] = names
    checks['dynamic_payloads_decrypted'] = decoded
    samples = []
    for index in range(10):
        page, info = client.request('/'+session+'/userRpm/StatusRpm.htm',label='authenticated_stability_sample')
        names, _ = status_fields(page,encryption)
        samples.append({'status':info['status'],'handler_fields':names,'passed':not login_page(page) and 'statusPara' in names and 'lanPara' in names})
        if index != 9:
            time.sleep(3)
    checks['authenticated_stability'] = {'samples':samples, 'interval_seconds':3, 'passed':all(x['passed'] for x in samples)}
    client.request('/'+session+'/userRpm/LogoutRpm.htm',label='logout')
    old, old_info = client.request('/'+session+'/userRpm/StatusRpm.htm',label='old_session_after_logout')
    checks['logout_revokes_session'] = authentication_denied(old,old_info)
    client.cookies.clear()
    bad, _ = perform_login(password+'x', 'one_invalid_password')
    checks['invalid_password_reply_fields'] = sorted(k for k in bad if not k.startswith('_'))
    checks['invalid_password_valid_flag'] = bad.get('valid') if type(bad.get('valid')) in (bool,int) else None
    if bad.get('_token_usable'):
        denied, denied_info = client.request('/'+bad['sessionId']+'/userRpm/StatusRpm.htm',label='protected_status_with_invalid_password')
        checks['invalid_password_rejected'] = authentication_denied(denied,denied_info)
    else:
        checks['invalid_password_rejected'] = not bad.get('valid') or not bad.get('_token_usable')
    login, encryption = perform_login(password,'known_password_relogin')
    checks['relogin_accepted'] = bool(login.get('valid') and login.get('_token_usable'))
    if checks['relogin_accepted']:
        session = login['sessionId']
        page, _ = client.request('/'+session+'/userRpm/StatusRpm.htm',label='status_after_relogin')
        names, _ = status_fields(page,encryption)
        checks['status_after_relogin'] = not login_page(page) and 'lanPara' in names
        client.request('/'+session+'/userRpm/LogoutRpm.htm',label='final_logout')


def run(root):
    is_940 = (root/'web/oem/model.conf').is_file()
    client, checks = GuestClient(keep_alive=not is_940), {}
    result = {'scope':'reconstructed_guest_functional_checks', 'authentication_code_modified':False,
              'guest_configuration_changed':False, 'checks':checks, 'requests':client.records,
              'functional_passed':False}
    password = 'Fx!'+secrets.token_hex(5)
    try:
        page, info = client.request('/', label='landing_page')
        checks['landing_page'] = info['status'] == 200 and ('pcPassword' in page or 'Login' in page)
        resources = ['/login/common.js','/login/tpEncrypt.js','/login/logo.png'] if is_940 else ['/js/lib.js','/js/tpEncrypt.js','/img/login/logo.png']
        checks['assets'] = []
        for path in resources:
            _, asset = client.request(path)
            checks['assets'].append({'path':path,'passed':asset['status']==200 and asset['bytes']>100})
        (wr940 if is_940 else wr841)(client,password,checks)
        result['guest_configuration_changed'] = bool(checks.get('password_created_via_vendor_api'))
        samples = []
        for _ in range(5):
            body, info = client.request('/js/oid_str.js' if not is_940 else '/login/common.js',label='stability_sample')
            samples.append({'status':info['status'],'sha256':info['sha256'],'bytes':info['bytes']})
            time.sleep(2)
        result['stability'] = {'samples':samples,'interval_seconds':2,
                               'passed':all(x['status']==200 and x['bytes']>100 for x in samples) and len({x['sha256'] for x in samples})==1}
        required = ['landing_page','anonymous_status_denied','login_accepted','authenticated_status_page','readonly_handler_observed']
        required += ['logout_revokes_session','invalid_password_rejected','relogin_accepted','status_after_relogin']
        result['functional_passed'] = all(checks.get(k) is True for k in required) and all(x['passed'] for x in checks['assets']) and result['stability']['passed']
        result['functional_passed'] &= checks.get('authenticated_stability',{}).get('passed',False)
    except Exception as exc:
        result['error_type'] = type(exc).__name__
        result['failure_stage'] = getattr(client,'last_label','initialization')
        result['last_response_framing'] = getattr(client,'last_response_framing',{})
        if checks.get('guest_configuration_change_attempted') and not checks.get('password_created_via_vendor_api'):
            result['guest_configuration_changed'] = None
        # Exception strings can contain response fragments or tokens.
    if checks.get('password_created_via_vendor_api'):
        result['guest_configuration_changed'] = True
    result['request_count'] = client.request_count
    client.close()
    return result
