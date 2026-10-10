import asyncio
from dataclasses import dataclass
from urllib.parse import quote

import aiohttp


@dataclass
class UsernameResult:
    source: str
    username: str
    status: str
    url: str
    http_status: int | None = None
    reason: str = ""


SOURCES = {
    "Reddit": "https://www.reddit.com/user/{username}/",
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Mastodon": "https://mastodon.social/@{username}",
}


def detect_profile(
    source: str,
    username: str,
    status: int,
    final_url: str,
    html: str,
) -> tuple[str, str]:

    text = html.lower()
    user = username.lower()

    # Общая защита от страниц авторизации
    if any(x in final_url.lower() for x in (
        "/users/sign_in",
        "/login",
        "/signin",
        "/auth",
    )):
        return "UNAVAILABLE", "Источник перенаправил на авторизацию"

    if status == 404:
        return "NOT_FOUND", "HTTP 404"

    if status in (401, 403, 429):
        return "UNAVAILABLE", f"HTTP {status}"

    if status != 200:
        return "UNKNOWN", f"HTTP {status}"

    # ---------------- GitHub ----------------
    if source == "GitHub":
        if (
            f'"/{user}"' in text
            or f'"/{user}/"' in text
        ) and (
            "github" in text
            and "profile" in text
        ):
            return "FOUND", "Профильные признаки GitHub обнаружены"

        if "not found" in text:
            return "NOT_FOUND", "GitHub: профиль не найден"

        return "UNKNOWN", "HTTP 200, но профиль не подтверждён"

    # ---------------- GitLab ----------------
    if source == "GitLab":
        if "/users/sign_in" in text:
            return "UNAVAILABLE", "GitLab требует авторизацию"

        if (
            f'/{user}' in text
            or f">{user}<" in text
        ) and "gitlab" in text:
            return "FOUND", "Профильные признаки GitLab обнаружены"

        if (
            "page not found" in text
            or "404" in text
        ):
            return "NOT_FOUND", "GitLab: профиль не найден"

        return "UNKNOWN", "HTTP 200, но профиль не подтверждён"

    # ---------------- Reddit ----------------
    if source == "Reddit":
        # Проверяем структурированные данные страницы,
        # а не просто наличие /user/username в HTML.
        reddit_profile_markers = (
            f'"name":"{user}"',
            f'"name": "{user}"',
            f'"username":"{user}"',
            f'"username": "{user}"',
        )

        if any(marker in text for marker in reddit_profile_markers):
            return "FOUND", "Профильные данные Reddit обнаружены"

        if (
            "nobody on reddit goes by that name" in text
            or "this page is unavailable" in text
            or "page not found" in text
        ):
            return "NOT_FOUND", "Reddit: профиль не найден"

        return "UNKNOWN", "HTTP 200, но профиль не подтверждён"

    # ---------------- Mastodon ----------------
    if source == "Mastodon":
        profile_url = f"/@{user}"

        if (
            profile_url in text
            and (
                f'"@{user}"' in text
                or f">{user}<" in text
            )
        ):
            return "FOUND", "Профильные признаки Mastodon обнаружены"

        if status == 404:
            return "NOT_FOUND", "Mastodon: профиль не найден"

        return "UNKNOWN", "HTTP 200, но профиль не подтверждён"

    return "UNKNOWN", "Нет правила проверки"


async def check_source(
    session: aiohttp.ClientSession,
    source: str,
    username: str,
) -> UsernameResult:

    safe_username = quote(username.strip(), safe="")
    url = SOURCES[source].format(username=safe_username)

    try:
        async with session.get(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as response:

            html = await response.text(errors="ignore")

            result_status, reason = detect_profile(
                source,
                username,
                response.status,
                str(response.url),
                html,
            )

            return UsernameResult(
                source=source,
                username=username,
                status=result_status,
                url=str(response.url),
                http_status=response.status,
                reason=reason,
            )

    except asyncio.TimeoutError:
        return UsernameResult(
            source=source,
            username=username,
            status="UNAVAILABLE",
            url=url,
            reason="Timeout",
        )

    except aiohttp.ClientError as error:
        return UsernameResult(
            source=source,
            username=username,
            status="UNAVAILABLE",
            url=url,
            reason=type(error).__name__,
        )


async def search_username(username: str) -> list[UsernameResult]:
    username = username.strip()

    if not username:
        raise ValueError("Username не может быть пустым")

    headers = {
        "User-Agent": (
            "myOSINT/1.0 "
            "(legitimate public-source OSINT research)"
        )
    }

    connector = aiohttp.TCPConnector(limit=10)

    async with aiohttp.ClientSession(
        headers=headers,
        connector=connector,
    ) as session:

        tasks = [
            check_source(session, source, username)
            for source in SOURCES
        ]

        return await asyncio.gather(*tasks)


def format_results(results: list[UsernameResult]) -> str:
    lines = []

    for result in results:
        icon = {
            "FOUND": "🟢",
            "NOT_FOUND": "🔴",
            "UNAVAILABLE": "⚪",
            "UNKNOWN": "🟡",
        }.get(result.status, "⚪")

        lines.append(
            f"{icon} {result.source}: {result.status}\n"
            f"   {result.url}\n"
            f"   {result.reason}"
        )

    return "\n\n".join(lines)
