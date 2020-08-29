import time

import requests
import requests_oauthlib
from flask import Flask, redirect, render_template, request, session, url_for
from oauthlib.oauth2 import InvalidClientIdError, MismatchingStateError

import config

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.FLASK_SECRET_KEY,
    SESSION_COOKIE_SECURE=True,
)

DISCORD_BASE_URL = 'https://discord.com/api/v6'


def create_discord_oauth_session(*, state=None, token=None):
    return requests_oauthlib.OAuth2Session(
        client_id=config.DISCORD_CLIENT_ID,
        token=token,
        state=state,
        scope=['identify', 'guilds.join'],
        redirect_uri=(request.url_root[:-1] + url_for('discord_callback')).replace('http://', 'https://'),
    )


def verify_hcaptcha(response: str) -> bool:
    ip = request.headers['X-Forwarded-For']
    if not ip:
        ip = None
    r = requests.post(
        'https://hcaptcha.com/siteverify',
        data={
            'secret': config.HCAPTCHA_SECRET_KEY,
            'response': response,
            'remoteip': ip,
            'sitekey': config.HCAPTCHA_SITE_KEY,
        },
    ).json()
    if r['hostname'] != config.HCAPTCHA_HOSTNAME:
        return False
    return r['success']


def get_user_id(access_token: str) -> str:
    response = requests.get(f'{DISCORD_BASE_URL}/users/@me', headers={'Authorization': f'Bearer {access_token}'})
    if response.status_code == 200:
        response = response.json()
        if user_id := response.get('id'):
            return user_id
    raise ValueError()


def revoke_token(access_token: str) -> requests.Response:
    return requests.post(
        'https://discord.com/api/oauth2/token/revoke',
        data={
            'token': access_token,
            'client_id': config.DISCORD_CLIENT_ID,
            'client_secret': config.DISCORD_CLIENT_SECRET,
        },
    )


def add_to_guild(access_token: str, user_id: str) -> requests.Response:
    return requests.put(
        f'{DISCORD_BASE_URL}/guilds/{config.DISCORD_SERVER_ID}/members/{user_id}',
        headers={'Authorization': f'Bot {config.DISCORD_BOT_TOKEN}'},
        json={'access_token': access_token, 'roles': [config.DISCORD_ROLE_ID]},
    )


def redirect_message_page(message: str, status_code: int = 200):
    session['message'] = message
    session['status_code'] = status_code
    session.pop('state', None)
    session.pop('time', None)
    session.pop('url', None)
    session.pop('state_time', None)
    session.pop('code_time', None)
    return redirect(url_for('root'))


def show_captcha():
    return render_template('captcha.html', hcaptcha_site_key=config.HCAPTCHA_SITE_KEY)


def check_captcha():
    hcaptcha_response = request.form.get('h-captcha-response', None)
    if not hcaptcha_response:
        return redirect_message_page('No CAPTCHA response', 400)
    if verify_hcaptcha(hcaptcha_response) is False:
        return redirect_message_page('Invalid CAPTCHA response', 400)


def if_timed_out(previous_time: int, timeout: int) -> bool:
    return previous_time + timeout <= time.time()


@app.route('/', methods=['GET', 'POST'])
def root():
    # GET
    # Has session.message and session.status_code -> from callback page, show message
    # Does not have both session.message and session.status_code -> first time, show CAPTCHA
    # POST
    # Has CAPTCHA response, create and store state, time and redirect
    if request.method == 'GET':
        # Redirected from callback with message and status code
        # If missing one, both are popped so it is cleared and it is ignored
        if (message := session.pop('message', None)) is not None and (
            status_code := session.pop('status_code', None)
        ) is not None:
            return message, status_code
        return show_captcha()
    # POST with CAPTCHA response
    if (captcha_response := check_captcha()) is not None:
        return captcha_response
    oauth_session = create_discord_oauth_session()
    authorization_url, state = oauth_session.authorization_url('https://discord.com/api/oauth2/authorize')
    session['state'] = state
    session['state_time'] = int(time.time())
    return redirect(authorization_url)


@app.route('/callback', methods=['GET', 'POST'])
def discord_callback():
    if request.method == 'GET':
        if session.get('url') and (incoming_time := session.get('code_time')):
            if if_timed_out(incoming_time, config.CODE_TIMEOUT) is True:
                return redirect_message_page('Timeout, please try again', 400)
            return show_captcha()
        if request.args.get('error') is not None:
            session.pop('state', None)
            return redirect_message_page('Discord OAuth Error, please try again', 400)
        if not request.args.get('code') or not request.args.get('state'):
            return redirect_message_page('Invalid request, please try again', 400)
        if not (incoming_time := session.pop('state_time', None)):
            return redirect_message_page('Invalid request, please try again', 400)
        if if_timed_out(incoming_time, config.STATE_TIMEOUT) is True:
            return redirect_message_page('Timeout, please try again', 400)
        session['url'] = request.url.replace('http://', 'https://')
        session['code_time'] = time.time()
        return redirect(url_for('discord_callback'))

    if (captcha_response := check_captcha()) is not None:
        return captcha_response

    if not (state := session.pop('state', None)):
        return redirect_message_page('Invalid request, please try again', 400)
    if not (incoming_time := session.pop('code_time', None)):
        return redirect_message_page('Invalid request, please try again', 400)
    if if_timed_out(incoming_time, config.CODE_TIMEOUT) is True:
        return redirect_message_page('Timeout, please try again', 400)
    if not (callback_url := session.pop('url', None)):
        return redirect_message_page('Invalid request, please try again', 400)
    oauth_session = create_discord_oauth_session(state=state)
    try:
        token = oauth_session.fetch_token(
            'https://discord.com/api/oauth2/token',
            client_secret=config.DISCORD_CLIENT_SECRET,
            authorization_response=callback_url,
        )
    except (MismatchingStateError, InvalidClientIdError):
        return redirect_message_page('Invalid request, please try again', 400)
    access_token = token['access_token']
    user_id = get_user_id(access_token)
    if config.user_is_in_whitelist(user_id) is False:
        return redirect_message_page('Unauthorized', 401)
    response = add_to_guild(access_token, user_id)
    revoke_token(access_token)
    status_code = response.status_code
    if status_code == 201:
        return redirect_message_page('You have been added')
    if status_code == 204:
        return redirect_message_page('You are already in the server', 400)
    if status_code == 403:
        return redirect_message_page('Bot does not have correct permissions', 500)
    if status_code == 400:
        if response.json()['code'] == 30001:
            return redirect_message_page('You are on 100 servers', 400)
    print(status_code, response.text)
    return redirect_message_page('Unknown error', 500)


if __name__ == '__main__':
    app.run()
