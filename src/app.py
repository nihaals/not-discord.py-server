import requests
import requests_oauthlib
from flask import Flask, redirect, render_template, request, session, url_for
from oauthlib.oauth2 import MismatchingStateError

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
    r = requests.post(
        'https://hcaptcha.com/siteverify',
        data={
            'secret': config.HCAPTCHA_SECRET_KEY,
            'response': response,
            # 'remoteip',
            'sitekey': config.HCAPTCHA_SITE_KEY,
        },
    )
    return r.json()['success']


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
    return redirect(url_for('root'))


@app.route('/', methods=['GET', 'POST'])
def root():
    if request.method == 'GET':
        if (message := session.pop('message', None)) is not None and (
            status_code := session.pop('status_code', None)
        ) is not None:
            return message, status_code
        return render_template('index.html', hcaptcha_site_key=config.HCAPTCHA_SITE_KEY)
    hcaptcha_response = request.form.get('h-captcha-response', None)
    if not hcaptcha_response:
        return 'No CAPTCHA response', 400
    if verify_hcaptcha(hcaptcha_response) is False:
        return 'Invalid CAPTCHA response', 400
    oauth_session = create_discord_oauth_session()
    authorization_url, state = oauth_session.authorization_url('https://discord.com/api/oauth2/authorize')
    session['state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def discord_callback():
    if request.args.get('error') is not None:
        session.pop('state', None)
        return redirect_message_page('Discord OAuth Error, please try again', 400)
    if not (state := session.pop('state', None)):
        return redirect_message_page('Invalid request, please try again', 400)
    oauth_session = create_discord_oauth_session(state=state)
    try:
        token = oauth_session.fetch_token(
            'https://discord.com/api/oauth2/token',
            client_secret=config.DISCORD_CLIENT_SECRET,
            authorization_response=request.url.replace('http://', 'https://'),
        )
    except MismatchingStateError:
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
