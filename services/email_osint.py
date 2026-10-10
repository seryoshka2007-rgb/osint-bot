import asyncio
import re
import socket
from dataclasses import dataclass
from email.utils import parseaddr

import aiohttp


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


@dataclass
class EmailResult:
    email: str
    normalized: str
    valid_format: bool
    local_part: str
    domain: str
    mx_records: list[str]
    domain_ip: str | None
    status: str
    reason: str


def normalize_email(email: str) -> str:
    return email.strip().lower()


def parse_email(email: str) -> tuple[str, str]:
    normalized = normalize_email(email)

    if not EMAIL_RE.fullmatch(normalized):
        return "", ""

    local_part, domain = normalized.rsplit("@", 1)
    return local_part, domain


async def resolve_mx(domain: str) -> list[str]:
    try:
        process = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "MX",
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

            parts = line.split()

            if len(parts) >= 2:
                host = parts[-1].rstrip(".")

                if host not in records:
                    records.append(host)

        return records

    except Exception:
        return []



async def resolve_ip(domain: str) -> str | None:
    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            lambda: socket.gethostbyname(domain),
        )

        return result

    except Exception:
        return None


async def check_domain_http(domain: str) -> int | None:
    url = f"https://{domain}"

    headers = {
        "User-Agent": (
            "myOSINT/1.0 "
            "(legitimate public-source OSINT research)"
        )
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
        ) as session:

            async with session.get(
                url,
                allow_redirects=True,
            ) as response:
                return response.status

    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def analyze_email(email: str) -> EmailResult:
    normalized = normalize_email(email)
    local_part, domain = parse_email(normalized)

    if not local_part or not domain:
        return EmailResult(
            email=email,
            normalized=normalized,
            valid_format=False,
            local_part="",
            domain="",
            mx_records=[],
            domain_ip=None,
            status="INVALID",
            reason="Некорректный формат email",
        )

    mx_task = resolve_mx(domain)
    ip_task = resolve_ip(domain)
    http_task = check_domain_http(domain)

    mx_records, domain_ip, http_status = await asyncio.gather(
        mx_task,
        ip_task,
        http_task,
    )

    if mx_records:
        status = "VALID_DOMAIN"
        reason = "Формат корректен, домен имеет MX-записи"
    else:
        status = "NO_MX"
        reason = "Формат корректен, MX-записи не обнаружены"

    return EmailResult(
        email=email,
        normalized=normalized,
        valid_format=True,
        local_part=local_part,
        domain=domain,
        mx_records=mx_records,
        domain_ip=domain_ip,
        status=status,
        reason=reason,
    )


def format_email_result(result: EmailResult) -> str:
    lines = [
        "📧 <b>Email OSINT</b>",
        "",
        f"Email: <code>{result.normalized}</code>",
        f"Статус: <b>{result.status}</b>",
        f"Причина: {result.reason}",
        "",
        f"Локальная часть: <code>{result.local_part or '—'}</code>",
        f"Домен: <code>{result.domain or '—'}</code>",
        f"IP домена: <code>{result.domain_ip or '—'}</code>",
    ]

    if result.mx_records:
        lines.append("")
        lines.append("📡 MX-записи:")
        for mx in result.mx_records:
            lines.append(f"• <code>{mx}</code>")

    return "\n".join(lines)
