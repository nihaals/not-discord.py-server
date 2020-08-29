import json
import os
from pathlib import Path
from typing import Iterator, Optional

import yaml


class _Config:
    def __init__(self) -> None:
        self._cached_json: Optional[dict] = None
        self._cached_whitelist: Optional[dict] = None

    def get_value(self, name: str) -> str:
        if env_value := os.environ.get(f'NDPS_{name.upper()}', None):
            return env_value
        if self._cached_json is None:
            try:
                with open(Path(__file__).parent.parent.joinpath('config.json')) as fp:
                    self._cached_json = json.load(fp)
            except FileNotFoundError:
                raise ValueError()
            except json.JSONDecodeError:
                raise ValueError()
        if config_value := self._cached_json.get(name):
            if isinstance(config_value, str) is False:
                raise ValueError()
            return config_value
        raise ValueError()

    def get_whitelist(self) -> Iterator[str]:
        if self._cached_whitelist is None:
            with open(Path(__file__).parent.parent.joinpath('whitelist.yml')) as fp:
                self._cached_whitelist = yaml.safe_load(fp)
        for user in self._cached_whitelist['users']:
            yield str(user['id'])


_config = _Config()

DISCORD_CLIENT_ID = _config.get_value('discord_client_id')
DISCORD_CLIENT_SECRET = _config.get_value('discord_client_secret')
DISCORD_BOT_TOKEN = _config.get_value('discord_bot_token')
DISCORD_SERVER_ID = _config.get_value('discord_server_id')
DISCORD_ROLE_ID = _config.get_value('discord_role_id')
FLASK_SECRET_KEY = _config.get_value('flask_secret_key')

HCAPTCHA_SECRET_KEY = _config.get_value('hcaptcha_secret_key')
HCAPTCHA_SITE_KEY = _config.get_value('hcaptcha_site_key')
HCAPTCHA_HOSTNAME = _config.get_value('hcaptcha_hostname')
_testing_captcha = _config.get_value('testing_captcha')

if _testing_captcha.lower() in ('true', 't', 'yes', 'y', '1'):
    HCAPTCHA_SECRET_KEY = '0x0000000000000000000000000000000000000000'
    HCAPTCHA_SITE_KEY = '10000000-ffff-ffff-ffff-000000000001'
    HCAPTCHA_HOSTNAME = 'dummy-key-pass'
elif _testing_captcha.lower() in ('false', 'f', 'no', 'n', '0'):
    pass
else:
    raise ValueError()


STATE_TIMEOUT = int(_config.get_value('state_timeout'))
CODE_TIMEOUT = int(_config.get_value('code_timeout'))

def user_is_in_whitelist(user_id: str) -> bool:
    for whitelisted_user_id in _config.get_whitelist():
        if whitelisted_user_id == user_id:
            return True
    return False
