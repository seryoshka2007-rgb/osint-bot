import re
from html import escape
from urllib.parse import quote

import aiohttp

API_URL = "https://api.xposedornot.com/v1/check-email/"
SOURCE_URL = "https://xposedornot.com/"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def check_email_breaches(email: str) -> dict:
    email = email.strip().lower()

    if not EMAIL_RE.fullmatch(email):
        return {
            "status": "INVALID",
            "email": email,
            "breaches": [],
            "message": "Некорректный формат email.",
        }

    url = API_URL + quote(email, safe="")
    timeout = aiohttp.ClientTimeout(total=25)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                params={"details": "true"},
                headers={
                    "User-Agent": "myOSINT/1.0",
                    "Accept": "application/json",
                },
            ) as response:
                if response.status == 429:
                    return {
                        "status": "RATE_LIMIT",
                        "email": email,
                        "breaches": [],
                        "message": "Достигнут лимит бесплатного API. Попробуй позже.",
                    }

                if response.status == 404:
                    return {
                        "status": "NOT_FOUND",
                        "email": email,
                        "breaches": [],
                        "message": "Совпадений в базе XposedOrNot не найдено.",
                    }

                if response.status != 200:
                    return {
                        "status": "ERROR",
                        "email": email,
                        "breaches": [],
                        "message": f"API вернул HTTP {response.status}.",
                    }

                data = await response.json(content_type=None)

        if not isinstance(data, dict):
            return {
                "status": "ERROR",
                "email": email,
                "breaches": [],
                "message": "Получен неожиданный ответ API.",
            }

        raw_details = data.get("breach_details", [])
        raw_names = data.get("breaches", [])
        details = []

        if isinstance(raw_details, list):
            details = [item for item in raw_details if isinstance(item, dict)]
        elif isinstance(raw_details, dict):
            details = [item for item in raw_details.values() if isinstance(item, dict)]

        names = []
        if isinstance(raw_names, list):
            for item in raw_names:
                if isinstance(item, str) and item.strip():
                    names.append(item.strip())
                elif isinstance(item, list):
                    names.extend(
                        value.strip() for value in item
                        if isinstance(value, str) and value.strip()
                    )
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("Name") or item.get("breach")
                    if isinstance(name, str) and name.strip():
                        names.append(name.strip())

        names = list(dict.fromkeys(names))
        if not names and details:
            names = list(dict.fromkeys(
                item["name"].strip()
                for item in details
                if isinstance(item.get("name"), str) and item["name"].strip()
            ))

        if not names:
            if data.get("Error") == "Not found" or data.get("status") == "success":
                return {
                    "status": "NOT_FOUND",
                    "email": email,
                    "breaches": [],
                    "details": [],
                    "message": "Совпадений в базе XposedOrNot не найдено.",
                }
            return {
                "status": "ERROR",
                "email": email,
                "breaches": [],
                "details": [],
                "message": "API не вернул список утечек.",
            }

        analytics = None
        try:
            analytics_url = "https://api.xposedornot.com/v1/breach-analytics"
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    analytics_url,
                    params={"email": email},
                    headers={
                        "User-Agent": "myOSINT/1.0",
                        "Accept": "application/json",
                    },
                ) as response:
                    if response.status == 200:
                        payload = await response.json(content_type=None)
                        if isinstance(payload, dict):
                            analytics = payload
        except (aiohttp.ClientError, TimeoutError, ValueError):
            analytics = None

        return {
            "status": "FOUND",
            "email": email,
            "breaches": names,
            "details": details,
            "analytics": analytics,
            "message": "Найдены совпадения в базе XposedOrNot.",
        }

    except (aiohttp.ClientError, TimeoutError) as exc:
        return {
            "status": "ERROR",
            "email": email,
            "breaches": [],
            "details": [],
            "message": f"Ошибка соединения: {type(exc).__name__}.",
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "email": email,
            "breaches": [],
            "details": [],
            "message": f"Ошибка обработки ответа: {type(exc).__name__}.",
        }


def format_breach_result(result: dict) -> str:
    email = escape(str(result.get("email", "")))
    status = result.get("status", "ERROR")
    message = escape(str(result.get("message", "")))
    breaches = result.get("breaches", [])
    details = result.get("details", [])
    analytics = result.get("analytics") or {}

    if status == "INVALID":
        return (
            "❌ <b>Проверка утечек</b>\n\n"
            f"📧 <code>{email}</code>\n\n{message}"
        )

    if status == "NOT_FOUND":
        return (
            "🟢 <b>Проверка утечек</b>\n\n"
            f"📧 <code>{email}</code>\n\n"
            "Совпадений в базе XposedOrNot не обнаружено.\n"
            "Это не гарантирует отсутствия адреса во всех существующих утечках.\n\n"
            f"Источник: {SOURCE_URL}"
        )

    if status != "FOUND":
        return (
            "⚠️ <b>Проверка утечек</b>\n\n"
            f"📧 <code>{email}</code>\n\n{message}\n\n"
            f"Источник: {SOURCE_URL}"
        )

    translations = {
        "email addresses": "Email-адреса",
        "usernames": "Имена пользователей",
        "passwords": "Пароли",
        "names": "Имена",
        "physical addresses": "Физические адреса",
        "phone numbers": "Номера телефонов",
        "ip addresses": "IP-адреса",
        "dates of birth": "Даты рождения",
        "geographic locations": "Геолокация",
        "genders": "Пол",
        "browsers": "Браузеры",
        "payment histories": "История платежей",
        "credit cards": "Данные банковских карт",
        "security questions": "Контрольные вопросы",
        "social media profiles": "Профили соцсетей",
        "personal health data": "Медицинские данные",
        "biometric data": "Биометрические данные",
        "account balances": "Баланс аккаунта",
        "employers": "Работодатели",
        "education levels": "Уровень образования",
        "marital statuses": "Семейное положение",
        "website activity": "Активность на сайте",
    }

    detail_by_name = {}
    for item in details:
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                detail_by_name[name.strip().casefold()] = item

    lines = [
        "🚨 <b>Breach Check — отчёт об утечках</b>",
        "",
        f"📧 <code>{email}</code>",
        f"🔴 Названий утечек в ответе API: <b>{len(breaches)}</b>",
        "",
    ]

    metrics = analytics.get("BreachMetrics") or {}
    risk_items = metrics.get("risk") or []
    if risk_items and isinstance(risk_items[0], dict):
        risk = risk_items[0]
        risk_label = risk.get("risk_label")
        risk_score = risk.get("risk_score")
        if risk_label is not None or risk_score is not None:
            label = escape(str(risk_label or "не указана"))
            score = escape(str(risk_score)) if risk_score is not None else "—"
            lines.extend([
                "📊 <b>Аналитика XposedOrNot</b>",
                f"⚠️ Уровень риска: <b>{label}</b> ({score}/100)",
            ])

    password_items = metrics.get("passwords_strength") or []
    if password_items and isinstance(password_items[0], dict):
        passwords = password_items[0]
        password_labels = {
            "PlainText": "открытый текст",
            "EasyToCrack": "легко взломать",
            "StrongHash": "стойкое хеширование",
            "Unknown": "неизвестно",
        }
        password_lines = [
            f"{password_labels[key]}: {passwords[key]}"
            for key in ("PlainText", "EasyToCrack", "StrongHash", "Unknown")
            if isinstance(passwords.get(key), int)
        ]
        if password_lines:
            lines.append("🔐 Типы паролей в аналитике: " + escape("; ".join(password_lines)))

    exposed_items = metrics.get("xposed_data") or []
    exposed_counts = []
    def collect_exposed(node):
        if isinstance(node, dict):
            name = node.get("name")
            value = node.get("value")
            if isinstance(name, str) and name.startswith("data_") and isinstance(value, (int, float)):
                exposed_counts.append((name[5:], value))
            for child in node.get("children", []):
                collect_exposed(child)
        elif isinstance(node, list):
            for child in node:
                collect_exposed(child)

    collect_exposed(exposed_items)
    exposed_counts.sort(key=lambda item: item[1], reverse=True)
    if exposed_counts:
        lines.append("🧾 <b>Частые категории данных в аналитике:</b>")
        for field, value in exposed_counts[:6]:
            lines.append(f"   • {escape(field)}: {value}")

    year_items = metrics.get("yearwise_details") or []
    if year_items and isinstance(year_items[0], dict):
        years = year_items[0]
        parsed_years = [
            (year[1:], count)
            for year, count in years.items()
            if isinstance(year, str) and year.startswith("y") and isinstance(count, int) and count > 0
        ]
        parsed_years.sort(key=lambda item: item[1], reverse=True)
        if parsed_years:
            lines.append("📅 Годы с наибольшими значениями в аналитике: " + escape(", ".join(
                f"{year}: {count}" for year, count in parsed_years[:5]
            )))

    pastes_summary = analytics.get("PastesSummary")
    if isinstance(pastes_summary, dict) and isinstance(pastes_summary.get("cnt"), int):
        lines.append(f"📋 Пасты в ответе API: {pastes_summary['cnt']}")

    if analytics:
        lines.append("ℹ️ Показатели аналитики агрегированы и не означают количество записей именно об этом адресе.")
        lines.append("")

    for index, name in enumerate(breaches[:25], 1):
        lines.append(f"<b>{index}. {escape(str(name))}</b>")
        item = detail_by_name.get(str(name).casefold(), {})

        company = item.get("company")
        if isinstance(company, dict):
            company_name = company.get("name")
            if isinstance(company_name, str) and company_name.strip():
                if company_name.strip().casefold() != str(name).casefold():
                    lines.append(f"   🏢 Компания: {escape(company_name.strip())}")

        breach_date = item.get("breach_date")
        if isinstance(breach_date, str) and breach_date.strip():
            lines.append(f"   📅 Дата: {escape(breach_date.strip())}")

        records = item.get("records_exposed")
        if isinstance(records, (int, float)) and not isinstance(records, bool):
            lines.append(f"   👥 Записей в утечке: {records:,}".replace(",", " "))

        exposed = item.get("exposed_data")
        if isinstance(exposed, list) and exposed:
            translated = []
            for field in exposed:
                if isinstance(field, str):
                    translated.append(
                        translations.get(field.strip().casefold(), field.strip())
                    )
            translated = list(dict.fromkeys(x for x in translated if x))
            if translated:
                lines.append(
                    "   🧾 Данные: " + escape(", ".join(translated[:8]))
                )

        security = item.get("security")
        if isinstance(security, dict):
            risk = security.get("password_risk")
            if isinstance(risk, str) and risk.strip():
                risk_translations = {
                    "plaintext": "пароли могли храниться открытым текстом",
                    "easy": "слабая защита паролей",
                    "hard": "пароли защищены хешированием",
                    "unknown": "уровень защиты неизвестен",
                }
                risk_text = risk_translations.get(risk.casefold(), risk)
                lines.append(f"   🔐 Пароли: {escape(risk_text)}")

        lines.append("")

    if len(breaches) > 25:
        lines.append(f"Показаны первые 25 из {len(breaches)} записей API.")

    lines.extend([
        "",
        "⚠️ Размер набора данных не равен числу утечек этого адреса.",
        "Данные получены из XposedOrNot и могут быть неполными.",
        f"Источник: {SOURCE_URL}",
    ])

    report = "\n".join(lines)

    if len(report) > 3900:
        # Убираем второстепенные строки, если подробности слишком длинные.
        compact = [
            "🚨 <b>Breach Check — отчёт об утечках</b>",
            "",
            f"📧 <code>{email}</code>",
            f"🔴 Названий утечек в ответе API: <b>{len(breaches)}</b>",
            "",
        ]
        compact_metrics = analytics.get("BreachMetrics") or {}
        compact_risks = compact_metrics.get("risk") or []
        if compact_risks and isinstance(compact_risks[0], dict):
            risk = compact_risks[0]
            label = escape(str(risk.get("risk_label") or "не указана"))
            score = escape(str(risk.get("risk_score"))) if risk.get("risk_score") is not None else "—"
            compact.extend([
                "📊 <b>Аналитика XposedOrNot</b>",
                f"⚠️ Уровень риска: <b>{label}</b> ({score}/100)",
            ])
        password_items = compact_metrics.get("passwords_strength") or []
        if password_items and isinstance(password_items[0], dict):
            passwords = password_items[0]
            labels = {
                "PlainText": "открытый текст",
                "EasyToCrack": "легко взломать",
                "StrongHash": "стойкое хеширование",
                "Unknown": "неизвестно",
            }
            parts = [
                f"{labels[key]}: {passwords[key]}"
                for key in ("PlainText", "EasyToCrack", "StrongHash", "Unknown")
                if isinstance(passwords.get(key), int)
            ]
            if parts:
                compact.append("🔐 Типы паролей в аналитике: " + escape("; ".join(parts)))
        pastes = analytics.get("PastesSummary")
        if isinstance(pastes, dict) and isinstance(pastes.get("cnt"), int):
            compact.append(f"📋 Пасты в ответе API: {pastes['cnt']}")
        if analytics:
            compact.append("ℹ️ Аналитика агрегированная, не число записей именно об этом адресе.")
        compact.append("")
        for index, name in enumerate(breaches[:25], 1):
            compact.append(f"<b>{index}. {escape(str(name))}</b>")
            item = detail_by_name.get(str(name).casefold(), {})
            exposed = item.get("exposed_data", [])
            if isinstance(exposed, list) and exposed:
                fields = [
                    translations.get(x.strip().casefold(), x.strip())
                    for x in exposed
                    if isinstance(x, str) and x.strip()
                ]
                if fields:
                    compact.append("   🧾 Данные: " + escape(", ".join(fields[:6])))
            date = item.get("breach_date")
            if isinstance(date, str) and date.strip():
                compact.append(f"   📅 Дата: {escape(date.strip())}")
            records = item.get("records_exposed")
            if isinstance(records, (int, float)) and not isinstance(records, bool):
                compact.append(
                    f"   👥 Записей в утечке: {records:,}".replace(",", " ")
                )
        compact.extend([
            "",
            "⚠️ Размер набора данных не равен числу утечек этого адреса.",
            f"Источник: {SOURCE_URL}",
        ])
        report = "\n".join(compact)

    return report
