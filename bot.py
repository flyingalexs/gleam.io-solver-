import requests
import re, random
import tls_client
from solver import solve
import hashlib, json
PROXYADDR = 'http://febtzqio:2jbxbx7yq4ls@38.154.227.167:5868'
PROXY = {
    'http': PROXYADDR,
    'https': PROXYADDR
}
CAMPAIGN_KEY = 'kFm1d'
HOST = 'gleam.io'
REFERER = 'https://gleam.io/kFm1d/tekken-8-key-giveaway'
OWNER_TOKEN = 'owner_token'
APP_SESSION = '_app_session'
SESSION = tls_client.Session(
    client_identifier="chrome_120",
    random_tls_extension_order=True
)
EMAIL = 'jagrit.soum.il12.34@gmail.com'
CSRF_TOKEN_PATTERN = re.compile(r'<meta name="csrf-token" content="([\w\d\/=\+]*)"')
ENTRY_METHOD = {
    "id": "7651539",
    "entry_type": "email_subscribe",
    "type_without_provider": "subscribe",
    "config": {},
    "worth": 1,
    "variable_worth": False,
    "provider": "email",
    "verified": False,
    "value_format": None,
    "must_verify": False,
    "requires_authentication": False,
    "can_authenticate": False,
    "requires_details": False,
    "display_information": None,
    "auth_for_details": False,
    "api_fallback": None,
    "auto_expandable": True,
    "expandable": False,
    "double_opt_in": False,
    "allowed_file_extensions": [],
    "config1": "Sign Up for the Intel® Gaming Access Newsletter",
    "config2": None,
    "config3": None,
    "config4": "Off",
    "config5": None,
    "config6": None,
    "config7": None,
    "config8": None,
    "config9": None,
    "config_selections": [],
    "iframe_url": None,
    "iframe_type": None,
    "accepts_file_types": None,
    "method_type": None,
    "config_toggle": False,
    "interval_seconds": 0,
    "next_interval_starts_at": 0,
    "actions_required": 0,
    "template": "",
    "normal_icon": "fas fa-envelope",
    "normal_icon_color": "",
    "unlocked_icon": "",
    "unlocked_icon_color": "",
    "completable": True,
    "maxlength": "",
    "restrict": None,
    "mandatory": True,
    "workflow": None,
    "timer_action": None,
    "limit": 0,
    "media_action": False,
    "preload_images": [],
    "tiers": [],
    "shows_content_after_entry": False,
    "kill_switch_message": None,
    "paid": False,
    "action_description": "Sign Up for the Intel® Gaming Access Newsletter",
    "required_auth_scopes": None,
    "fallback_to_details_submission": False,
    "disabled_options": None
}
ENTRY_METHOD_ID = ENTRY_METHOD['id']
ENTRY_METHOD_TYPE = ENTRY_METHOD['entry_type']






def entryMethodHashed(contestant_id, entry_method):
    entry_method_id = entry_method['id']
    entry_type = entry_method['entry_type']
    concatenated_str = '-'.join([str(-contestant_id), str(entry_method_id), entry_type, CAMPAIGN_KEY])
    hashed = hashlib.sha256(concatenated_str.encode()).hexdigest()
    return hashed
def fingerprintHash(base):
    is_bad = False
    hashed = hashlib.md5((base + ("+" if is_bad else "")).encode()).hexdigest()
    return base + "." + hashed
def cookies() -> dict:
    main_url = 'https://publisher.scrappey.com/api/v1?key=z9xnsgYmVZZmaiaYGKCDsJXShXrqyjUnIkGSHwHIugVwftijzUJZdsgkSCXE'
    res = SESSION.post(main_url, json={"cmd": "request.get",
                                        "url": "https://gleam.io/kFm1d/tekken-8-key-giveaway"
                                        })
    cookiesl = res.json()['solution']['cookies']
    text = res.json()['solution']['response']
    cookie = {cookie["name"]: cookie["value"] for cookie in cookiesl}
    cookiestring = res.json()['solution']['cookieString']
    _app_session = cookie[APP_SESSION]
    owner_token = cookie[OWNER_TOKEN]
    csrf_token_match = CSRF_TOKEN_PATTERN.search(text)
    print('Got values!!!')
    csrf_token = csrf_token_match.group(1) if csrf_token_match else None
    if csrf_token is None:
        print('Got no CSRF-Token retrying..')
        cookies()
    return owner_token, csrf_token, _app_session, cookiestring
def cookie_value(header, name):
    cookie = next((c for c in header['Set-Cookie'] if name in c), None)
    if not cookie:
        return None
    return cookie.split(name + '=')[1].split(';')[0]
def random_fingerprint(length=32, possible=None):
    if possible is None:
        possible = '0123456789abcdef'
        return ''.join(random.choice(possible) for _ in range(length))

def csrf_retrieve(text) -> str:
    csrf_token_match = CSRF_TOKEN_PATTERN.search(text)
    csrf_token = csrf_token_match.group(1) if csrf_token_match else None
    return csrf_token
def make_contestant(email, o, cookie, csrf, name='Moody', date_of_birth='08/12/1990'):
    print(f"Creating contestant with e-mail {email}, name: {name}, DOB: {date_of_birth}")
    
    headers = {
        'Referer': REFERER,
        'Cookie': cookie,
        'X-CSRF-Token': csrf,
        'X-Ref': 'kFm1dtGFK4fFaR83M',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
    }
    
    payload = {
        'campaign_key': CAMPAIGN_KEY,
        'contestant': {'name': name, 'email': email, 'date_of_birth': date_of_birth},
        'additional_details': True
    }
    
    try:
        response = SESSION.post('https://gleam.io/set-contestant', json=payload, headers=headers, proxy=PROXYADDR)
        data = response.json()
        
        _app_session = response.cookies.get(APP_SESSION)
        new_owner_token = response.cookies.get(OWNER_TOKEN)
        print(response.cookies)
        
        if not _app_session:
            raise ValueError("Failed to get session or owner token")
        
        print(f"Made contestant: {data} and received session ID: {_app_session}")
        
        return {
            'contestant': data,
            '_app_session': _app_session,
            'owner_token': o 
        }
    
    except Exception as e:
        print(f"Failed to make contestant: {str(e)}")
        raise

def makeEntry(contestant_id, _app_session, entry_method, fingerprint, owner_token, csrf_token):
    data = {}
    token = solve()
    data['details'] = None
    data['h'] = entryMethodHashed(contestant_id, entry_method)
    data['fingerprint'] = fingerprintHash(fingerprint)
    data['challenge_response'] = token
    data["use_turnstile"] = True
    data['use_hcaptcha'] = False

    print(f"Creating entry using data: {json.dumps(data)} and session: {_app_session}")

    cookie = f"_app_session={_app_session};owner_token={owner_token};"
    print('Using cookie: ' + cookie)
    print('Using csrf_token: ' + csrf_token)
    print(f"Sending data: {json.dumps(data)}")

    url = f"https://gleam.io/enter/{CAMPAIGN_KEY}/{entry_method['id']}"
    headers = {
        'Origin': 'https://gleam.io',
        'Referer': REFERER,
        'Host': HOST,
        'Cookie': cookie,
        'X-CSRF-Token': csrf_token
    }
    response = SESSION.post(url, json=data, headers=headers, proxy=PROXYADDR)

    if response.status_code != 200:
        raise Exception('failed: ' + response.text)
    else:
        response_data = response.json()
        if 'error' in response_data:
            raise Exception(response_data['error'])
        else:
            return response_data

o, c, a, co = cookies()
fpr = random_fingerprint()
print('Finger Print: ',fpr)
print('Using Token: ',c)
print('Using Email: ',EMAIL)
result = make_contestant(EMAIL,o, co, c)
c_data, a, o = result['contestant'], result[APP_SESSION], result[OWNER_TOKEN]
print(c_data)
c_id = c_data['contestant']['id']
result_2 = makeEntry(c_id, a, ENTRY_METHOD, fpr, o, c)
print(result_2)