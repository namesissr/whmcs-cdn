"""Outbound providers of the customer notification engine (SPEC §23.5): SMS (Kavenegar, SMS.ir,
Melipayamak) and the customer Telegram / Bale bots (Telegram-compatible Bot API).

All HTTP goes through httpx (HTTPS_PROXY / ALL_PROXY honoured like the operator alerts), 10 s timeouts,
an injectable transport for tests (`transport`). Keys and tokens come from the environment only and
never appear in a log line, an error text, the database or an API answer: Kavenegar and the bot APIs
carry the secret in the URL path, so request URLs are never logged and errors carry only the provider
status. The provider endpoints are assumptions to verify on staging.

A provider is a class with `send(phone, text) -> (ok, permanent, provider_id)`; adding one = one class
plus one entry in SMS_PROVIDERS.
"""

import logging
import re

import httpx

from .config import settings

log = logging.getLogger("pcdn.notify")

TIMEOUT = 10.0
# tests inject an httpx.MockTransport here (SMS and bot calls)
transport: httpx.BaseTransport | None = None


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, transport=transport, follow_redirects=False)


def scrub(text: str | None) -> str:
    """Remove every configured provider secret from a text (defence in depth)."""
    text = str(text or "")
    for secret in (settings.sms_api_key, settings.telegram_customer_bot_token, settings.bale_bot_token):
        if secret:
            text = text.replace(secret, "***")
    return text[:200]


def _outcome(status: int) -> tuple[bool, bool]:
    """(ok, permanent) of an HTTP status: 2xx ok; other 4xx (except 408/429) permanent."""
    if 200 <= status < 300:
        return True, False
    return False, 400 <= status < 500 and status not in (408, 429)


class SmsProvider:
    name = ""
    default_url = ""

    def __init__(self, api_key: str, sender: str, url: str = ""):
        self.api_key, self.sender, self.url = api_key, sender, (url or self.default_url).rstrip("/")

    def request(self, client: httpx.Client, phone: str, text: str) -> httpx.Response:  # pragma: no cover
        raise NotImplementedError

    def provider_id(self, r: httpx.Response) -> str | None:
        return None

    def send(self, phone: str, text: str) -> tuple[bool, bool, str | None]:
        try:
            with _client() as c:
                r = self.request(c, phone, text)
        except httpx.HTTPError as e:
            # never the URL (it may hold the key): only the exception type
            log.warning("sms %s: request failed (%s)", self.name, type(e).__name__)
            return False, False, None
        ok, permanent = _outcome(r.status_code)
        if not ok:
            log.warning("sms %s: HTTP %s", self.name, r.status_code)
            return False, permanent, None
        try:
            pid = self.provider_id(r)
        except Exception:  # noqa: BLE001 - an odd success body is still a success
            pid = None
        return True, False, pid


class Kavenegar(SmsProvider):
    """POST https://api.kavenegar.com/v1/{key}/sms/send.json, form receptor / sender / message."""
    name = "kavenegar"
    default_url = "https://api.kavenegar.com/v1"

    def request(self, client, phone, text):
        return client.post(f"{self.url}/{self.api_key}/sms/send.json",
                           data={"receptor": phone, "sender": self.sender, "message": text})

    def provider_id(self, r):
        entries = (r.json() or {}).get("entries") or []
        return str(entries[0].get("messageid")) if entries else None


class SmsIr(SmsProvider):
    """POST https://api.sms.ir/v1/send/bulk, header X-API-KEY, JSON lineNumber / messageText / mobiles."""
    name = "smsir"
    default_url = "https://api.sms.ir/v1"

    def request(self, client, phone, text):
        return client.post(f"{self.url}/send/bulk", headers={"X-API-KEY": self.api_key, "Accept": "application/json"},
                           json={"lineNumber": self.sender, "messageText": text, "mobiles": [phone]})

    def provider_id(self, r):
        data = (r.json() or {}).get("data") or {}
        return str(data.get("packId")) if data.get("packId") else None


class Melipayamak(SmsProvider):
    """POST https://console.melipayamak.com/api/send/simple/{key}, JSON from / to / text."""
    name = "melipayamak"
    default_url = "https://console.melipayamak.com/api"

    def request(self, client, phone, text):
        return client.post(f"{self.url}/send/simple/{self.api_key}",
                           json={"from": self.sender, "to": phone, "text": text})

    def provider_id(self, r):
        rec = (r.json() or {}).get("recId")
        return str(rec) if rec else None


SMS_PROVIDERS = {"kavenegar": Kavenegar, "smsir": SmsIr, "melipayamak": Melipayamak}


def sms_provider() -> SmsProvider | None:
    cls = SMS_PROVIDERS.get(settings.sms_provider)
    if cls is None or not settings.sms_api_key:
        return None
    return cls(settings.sms_api_key, settings.sms_sender, settings.sms_api_url)


# ------------------------------------------------------------------ bots (Telegram-compatible)

class BotApi:
    def __init__(self, channel: str, base: str, token: str, username: str):
        self.channel, self.base, self.token, self.username = channel, base.rstrip("/"), token, username

    def _url(self, method: str) -> str:
        return f"{self.base}/bot{self.token}/{method}"

    def send_message(self, chat_id: str, text: str) -> tuple[bool, bool, str | None]:
        try:
            with _client() as c:
                r = c.post(self._url("sendMessage"), json={"chat_id": chat_id, "text": text})
        except httpx.HTTPError as e:
            log.warning("%s bot: sendMessage failed (%s)", self.channel, type(e).__name__)
            return False, False, None
        ok, permanent = _outcome(r.status_code)
        if not ok:
            log.warning("%s bot: sendMessage HTTP %s", self.channel, r.status_code)
            return False, permanent, None
        try:
            mid = ((r.json() or {}).get("result") or {}).get("message_id")
        except ValueError:
            mid = None
        return True, False, str(mid) if mid is not None else None

    def get_updates(self, offset: int | None) -> list[dict]:
        params = {"timeout": 0, "allowed_updates": '["message"]'}
        if offset is not None:
            params["offset"] = offset
        try:
            with _client() as c:
                r = c.get(self._url("getUpdates"), params=params)
        except httpx.HTTPError as e:
            log.warning("%s bot: getUpdates failed (%s)", self.channel, type(e).__name__)
            return []
        if r.status_code != 200:
            log.warning("%s bot: getUpdates HTTP %s", self.channel, r.status_code)
            return []
        try:
            data = r.json()
        except ValueError:
            return []
        res = data.get("result") if isinstance(data, dict) else None
        return [u for u in (res or []) if isinstance(u, dict)]


def bot(channel: str) -> BotApi | None:
    if channel == "telegram" and settings.telegram_customer_bot_token:
        return BotApi("telegram", settings.telegram_api_url, settings.telegram_customer_bot_token,
                      settings.telegram_customer_bot_username)
    if channel == "bale" and settings.bale_bot_token:
        return BotApi("bale", settings.bale_api_url, settings.bale_bot_token, settings.bale_bot_username)
    return None


def deep_link(channel: str, code: str) -> str | None:
    if channel == "telegram" and settings.telegram_customer_bot_username:
        return f"https://t.me/{settings.telegram_customer_bot_username}?start={code}"
    if channel == "bale" and settings.bale_bot_username:
        return f"https://ble.ir/{settings.bale_bot_username}?start={code}"
    return None


def configured(channel: str) -> bool:
    if channel == "email":
        return True
    if channel == "sms":
        return sms_provider() is not None
    return bot(channel) is not None


def status() -> dict:
    """GET /api/v1/notifications/status: never a key or token."""
    return {
        "sms": {"provider": settings.sms_provider if settings.sms_provider in SMS_PROVIDERS else None,
                "configured": configured("sms")},
        "bale": {"configured": configured("bale"), "username": settings.bale_bot_username or None},
        "telegram": {"configured": configured("telegram"),
                     "username": settings.telegram_customer_bot_username or None},
        "email": {"configured": True},
    }


PHONE_RE = re.compile(r"^\+989\d{9}$")
INTL_PHONE_RE = re.compile(r"^\+[1-9]\d{7,14}$")
