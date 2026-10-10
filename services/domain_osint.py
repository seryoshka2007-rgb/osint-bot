import asyncio
import socket
from dataclasses import dataclass

import aiohttp


@dataclass
class DomainResult:
    domain: str
    a_records: list[str]
    aaaa_records: list[str]
    mx_records: list[str]
    ns_records: list[str]
    txt_records: list[str]
    http_status: int | None
    https_status: int | None
    http_url: str
    https_url: str
    status: str
    reason: str


async def dig_records(domain: str, record_type: str) -> list[str]:
    try:
        process = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            record_type,
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await process.communicate()

        if process.returncode != 0:
            return []

        records = []

        for line in stdout.decode(
            "utf-8",
            errors="ignore",
        ).splitlines():

            line = line.strip()

            if not line:
                continue

            if record_type in ("MX", "NS"):
                parts = line.split()
                value = parts[-1].rstrip(".")
            elif record_type == "TXT":
                value = line
            else:
                value = line

            if value not in records:
                records.append(value)

        return records

    except Exception:
        return []


async def check_http(
    session: aiohttp.ClientSession,
    scheme: str,
    domain: str,
) -> int | None:
    url = f"{scheme}://{domain}"

    try:
        async with session.get(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            return response.status

    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def analyze_domain(domain: str) -> DomainResult:
    domain = domain.strip().lower()

    if domain.startswith("http://"):
        domain = domain[7:]

    if domain.startswith("https://"):
        domain = domain[8:]

    domain = domain.split("/")[0].split(":")[0]

    if not domain or "." not in domain:
        return DomainResult(
            domain=domain,
            a_records=[],
            aaaa_records=[],
            mx_records=[],
            ns_records=[],
            txt_records=[],
            http_status=None,
            https_status=None,
            http_url=f"http://{domain}",
            https_url=f"https://{domain}",
            status="INVALID",
            reason="Некорректный домен",
        )

    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    results = await asyncio.gather(
        *(dig_records(domain, record_type) for record_type in record_types)
    )

    a_records, aaaa_records, mx_records, ns_records, txt_records = results

    headers = {
        "User-Agent": (
            "myOSINT/1.0 "
            "(legitimate public-source OSINT research)"
        )
    }

    async with aiohttp.ClientSession(headers=headers) as session:
        http_status, https_status = await asyncio.gather(
            check_http(session, "http", domain),
            check_http(session, "https", domain),
        )

    if a_records or aaaa_records or ns_records:
        status = "FOUND"
        reason = "DNS-инфраструктура домена обнаружена"
    else:
        status = "NOT_FOUND"
        reason = "DNS-записи домена не обнаружены"

    return DomainResult(
        domain=domain,
        a_records=a_records,
        aaaa_records=aaaa_records,
        mx_records=mx_records,
        ns_records=ns_records,
        txt_records=txt_records,
        http_status=http_status,
        https_status=https_status,
        http_url=f"http://{domain}",
        https_url=f"https://{domain}",
        status=status,
        reason=reason,
    )


def format_domain_result(result: DomainResult) -> str:
    lines = [
        "🌐 <b>Domain OSINT</b>",
        "",
        f"Домен: <code>{result.domain}</code>",
        f"Статус: <b>{result.status}</b>",
        f"Причина: {result.reason}",
        "",
        f"HTTP: <code>{result.http_status or '—'}</code>",
        f"HTTPS: <code>{result.https_status or '—'}</code>",
    ]

    sections = [
        ("A", result.a_records),
        ("AAAA", result.aaaa_records),
        ("MX", result.mx_records),
        ("NS", result.ns_records),
        ("TXT", result.txt_records),
    ]

    for name, records in sections:
        if records:
            lines.append("")
            lines.append(f"📡 {name}:")
            for record in records[:15]:
                lines.append(f"• <code>{record}</code>")

    return "\n".join(lines)
