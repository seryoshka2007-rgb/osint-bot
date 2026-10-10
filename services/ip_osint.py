import asyncio
import ipaddress
import socket
from dataclasses import dataclass

import aiohttp


@dataclass
class IPResult:
    ip: str
    version: str
    reverse_dns: list[str]
    ptr: str | None
    hostname: str | None
    country: str | None
    region: str | None
    city: str | None
    organization: str | None
    asn: str | None
    http_status: int | None
    https_status: int | None
    status: str
    reason: str


async def reverse_dns(ip: str) -> tuple[list[str], str | None]:
    try:
        hostname, aliases, _ = await asyncio.to_thread(
            socket.gethostbyaddr,
            ip,
        )

        names = []

        for name in [hostname, *aliases]:
            if name and name not in names:
                names.append(name)

        return names, hostname

    except (socket.herror, socket.gaierror, OSError):
        return [], None


async def ipinfo(
    session: aiohttp.ClientSession,
    ip: str,
) -> dict:
    url = f"https://ipinfo.io/{ip}/json"

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:

            if response.status != 200:
                return {}

            data = await response.json(content_type=None)

            return {
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "organization": data.get("org"),
                "asn": (
                    data.get("org", "").split(" ", 1)[0]
                    if data.get("org")
                    else None
                ),
            }

    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return {}


async def check_http(
    session: aiohttp.ClientSession,
    scheme: str,
    ip: str,
) -> int | None:

    url = f"{scheme}://{ip}"

    try:
        async with session.get(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as response:
            return response.status

    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def analyze_ip(ip: str) -> IPResult:
    ip = ip.strip()

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return IPResult(
            ip=ip,
            version="",
            reverse_dns=[],
            ptr=None,
            hostname=None,
            country=None,
            region=None,
            city=None,
            organization=None,
            asn=None,
            http_status=None,
            https_status=None,
            status="INVALID",
            reason="Некорректный IP-адрес",
        )

    version = f"IPv{parsed.version}"

    headers = {
        "User-Agent": (
            "myOSINT/1.0 "
            "(legitimate public-source OSINT research)"
        )
    }

    async with aiohttp.ClientSession(headers=headers) as session:
        dns_task = reverse_dns(ip)
        info_task = ipinfo(session, ip)
        http_task = check_http(session, "http", ip)
        https_task = check_http(session, "https", ip)

        (
            reverse_names,
            hostname,
        ), info, http_status, https_status = await asyncio.gather(
            dns_task,
            info_task,
            http_task,
            https_task,
        )

    if reverse_names or info:
        status = "FOUND"
        reason = "Публичная информация об IP обнаружена"
    else:
        status = "UNKNOWN"
        reason = "Публичная информация не получена"

    return IPResult(
        ip=ip,
        version=version,
        reverse_dns=reverse_names,
        ptr=hostname,
        hostname=hostname,
        country=info.get("country"),
        region=info.get("region"),
        city=info.get("city"),
        organization=info.get("organization"),
        asn=info.get("asn"),
        http_status=http_status,
        https_status=https_status,
        status=status,
        reason=reason,
    )


def format_ip_result(result: IPResult) -> str:
    lines = [
        "🖥 <b>IP OSINT</b>",
        "",
        f"IP: <code>{result.ip}</code>",
        f"Тип: <code>{result.version}</code>",
        f"Статус: <b>{result.status}</b>",
        f"Причина: {result.reason}",
        "",
        f"🌍 Страна: <code>{result.country or '—'}</code>",
        f"📍 Регион: <code>{result.region or '—'}</code>",
        f"🏙 Город: <code>{result.city or '—'}</code>",
        f"🏢 Организация: <code>{result.organization or '—'}</code>",
        f"🔢 ASN: <code>{result.asn or '—'}</code>",
        f"🔗 Reverse DNS: <code>{result.ptr or '—'}</code>",
        f"🌐 HTTP: <code>{result.http_status or '—'}</code>",
        f"🔒 HTTPS: <code>{result.https_status or '—'}</code>",
    ]

    if result.reverse_dns:
        lines.append("")
        lines.append("📡 Имена:")
        for name in result.reverse_dns[:10]:
            lines.append(f"• <code>{name}</code>")

    return "\n".join(lines)
