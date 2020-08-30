import time
from typing import List, Optional

import discord
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

DISCORD_WEBHOOK = discord.Webhook.from_url(
    config.DISCORD_WEBHOOK_URL,
    adapter=discord.RequestsWebhookAdapter(requests.Session()),
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


class DiscordUser:
    def __init__(
        self,
        id_: str,
        username: str,
        discriminator: str,
        avatar: Optional[str],
        mfa_enabled: Optional[bool],
    ) -> None:
        self.id = id_
        self.username = username
        self.discriminator = discriminator
        self._avatar = avatar
        self.mfa_enabled = mfa_enabled

    def __str__(self) -> str:
        return f'{self.username}#{self.discriminator}'

    @classmethod
    def from_dict(cls, data: dict):
        if 'mfa_enabled' not in data:
            send_webhook('MFA Enabled not available\n' + repr(data))
        return cls(
            data['id'],
            data['username'],
            data['discriminator'],
            data['avatar'],
            data.get('mfa_enabled'),
        )

    @property
    def avatar_url(self) -> str:
        if self._avatar is None:
            return f'https://cdn.discordapp.com/embed/avatars/{self.discriminator % 5}.png'
        if self._avatar.startswith('a_'):
            ext = 'gif'
        else:
            ext = 'png'
        return f'https://cdn.discordapp.com/avatars/{self.id}/{self._avatar}.{ext}'

    @property
    def mention(self) -> str:
        return f'<@{self.id}>'

    def as_embed(self, *, title: str = None, description: str = None) -> discord.Embed:
        embed = discord.Embed()
        if title is not None:
            embed.title = title
        if description is not None:
            embed.description = description
        embed.set_author(name=str(self), icon_url=self.avatar_url)
        embed.add_field(name='User ID', value=self.id)
        embed.add_field(name='Mention', value=self.mention)
        embed.add_field(name='Avatar URL', value=self.avatar_url)
        created_at = discord.utils.snowflake_time(int(self.id)).strftime('%A %d %B %Y at %H:%M:%S UTC')
        embed.add_field(name='Created at', value=created_at)
        return embed


def get_user(access_token: str) -> DiscordUser:
    response = requests.get(f'{DISCORD_BASE_URL}/users/@me', headers={'Authorization': f'Bearer {access_token}'})
    if response.status_code == 200:
        response = response.json()
        return DiscordUser.from_dict(response)
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


def send_webhook(
    content: str = None,
    *,
    username: str = None,
    avatar_url: str = None,
    embed: discord.Embed = None,
    embeds: List[discord.Embed] = None,
    allowed_mentions: discord.AllowedMentions = None,
):
    if allowed_mentions is None:
        allowed_mentions = discord.AllowedMentions(everyone=False, users=False, roles=False)
    DISCORD_WEBHOOK.send(
        content=content,
        username=username,
        avatar_url=avatar_url,
        embed=embed,
        embeds=embeds,
        allowed_mentions=allowed_mentions,
    )


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
    user = get_user(access_token)
    if config.user_is_in_whitelist(user.id) is False:
        send_webhook(embed=user.as_embed(title='User not in whitelist'))
        return redirect_message_page('Unauthorized', 401)
    if user.mfa_enabled is False:
        send_webhook(embed=user.as_embed(title='User not using MFA'))
        return redirect_message_page('You are not using multi-factor authentication', 400)
    response = add_to_guild(access_token, user.id)
    revoke_token(access_token)
    status_code = response.status_code
    if status_code == 201:
        send_webhook(embed=user.as_embed(title='User added'))
        return redirect_message_page('You have been added')
    if status_code == 204:
        send_webhook(embed=user.as_embed(title='User already in server'))
        return redirect_message_page('You are already in the server', 400)
    if status_code == 403:
        send_webhook('add_to_guild received a 403')
        return redirect_message_page('Bot does not have correct permissions', 500)
    if status_code == 400:
        if response.json()['code'] == 30001:
            send_webhook(embed=user.as_embed(title='User on 100 guilds'))
            return redirect_message_page('You are on 100 servers', 400)
    print(status_code, response.text)
    send_webhook(f'{status_code}\n{response.text}')
    return redirect_message_page('Unknown error', 500)


if __name__ == '__main__':
    app.run()
