"""
SecureBank — Python Server SDK v4 (fingerprint_server_sdk)

Uses fingerprint_server_sdk's FingerprintApi to query an event by event_id.
Returns v4 flat response structure (snake_case fields).

Usage: python3 python-sdk.py <event_id>
"""

import sys
import os
import json
import datetime
from dotenv import load_dotenv
import fingerprint_server_sdk
from fingerprint_server_sdk.configuration import Region
from fingerprint_server_sdk.exceptions import ApiException
from fingerprint_server_sdk.models import ErrorResponse

load_dotenv()
API_KEY = os.environ.get('FP_SERVER_API_KEY')
if not API_KEY:
    sys.exit('Missing FP_SERVER_API_KEY in .env')
PYTHON_SDK_LOG = 'python_sdk_response.txt'

configuration = fingerprint_server_sdk.Configuration(
    api_key=API_KEY,
    region=Region.AP,
)


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 python-sdk.py <event_id>')
        sys.exit(1)

    event_id = sys.argv[1]

    try:
        api = fingerprint_server_sdk.FingerprintApi(configuration)
        event = api.get_event(event_id)
    except ApiException as e:
        if e.body:
            err = ErrorResponse.from_json(e.body)
            if err and err.error:
                print(f'API error [{e.status}]: {err.error.code} — {err.error.message}')
            else:
                print(f'API error [{e.status}]: {e.body}')
        else:
            print(f'API error [{e.status}]')
        sys.exit(1)

    # v4 flat structure — access fields directly
    ident   = event.identification   if hasattr(event, 'identification')   else None
    browser = event.browser_details  if hasattr(event, 'browser_details')  else None
    ip_info = event.ip_info          if hasattr(event, 'ip_info')          else None

    city = 'unknown'
    if ip_info:
        v4 = getattr(ip_info, 'v4', None)
        v6 = getattr(ip_info, 'v6', None)
        geo = getattr(v4 or v6, 'geolocation', None)
        city = getattr(geo, 'city_name', 'unknown') if geo else 'unknown'

    print('\nPython SDK response (v4):')
    print(f'  event_id      : {getattr(event, "event_id", None)}')
    print(f'  visitorId     : {getattr(ident, "visitor_id", None)}')
    print(f'  linkedId      : {getattr(event, "linked_id", None)}')
    conf = getattr(ident, 'confidence', None)
    print(f'  confidence    : {getattr(conf, "score", None)}')
    print(f'  suspectScore  : {getattr(event, "suspect_score", None)}')
    print(f'  browserName   : {getattr(browser, "browser_name", None)}')
    print(f'  os            : {getattr(browser, "os", None)}')
    print(f'  ip            : {getattr(event, "ip_address", None)}')
    print(f'  city          : {city}')
    print(f'  bot           : {getattr(event, "bot", None)}')
    print(f'  vpn           : {getattr(event, "vpn", None)}')
    print(f'  proxy         : {getattr(event, "proxy", None)}')

    # Write raw response to file
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw = json.dumps(json.loads(event.to_json()), indent=2) if hasattr(event, 'to_json') else json.dumps(event.__dict__, default=str, indent=2)
    separator = '─' * 60
    entry = f'\n{separator}\nTimestamp : {timestamp}\nEventId   : {event_id}\n{raw}\n'

    with open(PYTHON_SDK_LOG, 'a') as f:
        f.write(entry)

    print(f'\nRaw response written to {PYTHON_SDK_LOG}')


if __name__ == '__main__':
    main()
