import asyncio
import logging
import os

from aiogram import Bot, Dispatcher, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command, CommandStart
from aiogram.types import Message, CallbackQuery
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv

from services.username_osint import search_username, format_results
from services.email_osint import analyze_email, format_email_result
from services.domain_osint import analyze_domain, format_domain_result
from services.ip_osint import analyze_ip, format_ip_result
from services.breach_osint import check_email_breaches, format_breach_result


load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set in .env")


router = Router()


def main_menu():
    builder = InlineKeyboardBuilder()
    builder.button(text="👤 Username OSINT", callback_data="osint_username")
    builder.button(text="📧 Email OSINT", callback_data="osint_email")
    builder.button(text="🌐 Domain OSINT", callback_data="osint_domain")
    builder.button(text="🖥 IP OSINT", callback_data="osint_ip")
    builder.button(text="🔐 Breach Check", callback_data="osint_breach")
    builder.button(text="ℹ️ О боте", callback_data="osint_info")
    builder.adjust(1)
    return builder.as_markup()


@router.message(CommandStart())
async def cmd_start(message: Message):
    await message.answer(
        "🔎 <b>myOSINT</b>\n\n"
        "Бот для анализа сведений из публичных источников.\n"
        "Выбери модуль в меню ниже или используй /info, чтобы узнать больше.\n\n"
        "Команды: /username, /email, /domain, /ip, /breach",
        parse_mode="HTML",
        reply_markup=main_menu(),
    )


@router.callback_query(lambda callback: callback.data == "osint_ip")
async def callback_ip(callback: CallbackQuery):
    await callback.answer()
    await callback.message.answer(
        "🖥 <b>IP OSINT</b>\n\n"
        "Отправь команду:\n"
        "<code>/ip 8.8.8.8</code>",
        parse_mode="HTML",
    )


@router.callback_query(lambda callback: callback.data == "osint_domain")
async def callback_domain(callback: CallbackQuery):
    await callback.answer()
    await callback.message.answer(
        "🌐 <b>Domain OSINT</b>\n\n"
        "Отправь команду:\n"
        "<code>/domain example.com</code>\n\n"
        "Например:\n"
        "<code>/domain google.com</code>",
        parse_mode="HTML",
    )


@router.callback_query(lambda callback: callback.data == "osint_email")
async def callback_email(callback: CallbackQuery):
    await callback.answer()
    await callback.message.answer(
        "📧 <b>Email OSINT</b>\n\n"
        "Отправь команду:\n"
        "<code>/email address@example.com</code>\n\n"
        "Например:\n"
        "<code>/email test@gmail.com</code>",
        parse_mode="HTML",
    )


@router.callback_query(lambda callback: callback.data == "osint_username")
async def callback_username(callback: CallbackQuery):
    await callback.answer()
    await callback.message.answer(
        "👤 <b>Username OSINT</b>\n\n"
        "Отправь команду:\n"
        "<code>/username username</code>\n\n"
        "Например:\n"
        "<code>/username test</code>",
        parse_mode="HTML",
    )


@router.callback_query(lambda callback: callback.data == "osint_breach")
async def callback_breach(callback: CallbackQuery):
    await callback.answer()
    await callback.message.answer(
        "🔐 <b>Breach Check</b>\n\n"
        "Проверь, встречался ли адрес электронной почты в известных утечках.\n"
        "Отправь команду:\n"
        "<code>/breach email@example.com</code>",
        parse_mode="HTML",
    )


async def send_bot_info(message: Message):
    await message.answer(
        "ℹ️ <b>О боте myOSINT</b>\n\n"
        "myOSINT помогает собирать и анализировать сведения из публичных источников. "
        "Результаты зависят от доступности источников и не гарантируют полноту данных.\n\n"
        "<b>Возможности:</b>\n"
        "👤 <b>Username OSINT</b> — поиск публичных профилей по имени пользователя.\n"
        "📧 <b>Email OSINT</b> — анализ адреса электронной почты.\n"
        "🌐 <b>Domain OSINT</b> — анализ домена.\n"
        "🖥 <b>IP OSINT</b> — анализ IP-адреса.\n"
        "🔐 <b>Breach Check</b> — проверка адреса на наличие в известных утечках.\n\n"
        "<b>Команды:</b>\n"
        "/start — главное меню\n"
        "/info — информация о боте\n"
        "/help — список команд\n"
        "/username имя — поиск имени пользователя\n"
        "/email адрес — анализ электронной почты\n"
        "/domain домен — анализ домена\n"
        "/ip адрес — анализ IP\n"
        "/breach адрес — проверка утечек",
        parse_mode="HTML",
    )


@router.callback_query(lambda callback: callback.data == "osint_info")
async def callback_info(callback: CallbackQuery):
    await callback.answer()
    await send_bot_info(callback.message)


@router.message(Command("info"))
async def cmd_info(message: Message):
    await send_bot_info(message)


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "🛠 <b>Доступные команды</b>\n\n"
        "/start — главное меню\n"
        "/info — описание бота и его возможностей\n"
        "/help — эта справка\n"
        "/username имя — поиск публичных профилей\n"
        "/email адрес — анализ электронной почты\n"
        "/domain домен — анализ домена\n"
        "/ip адрес — анализ IP-адреса\n"
        "/breach адрес — проверка на известные утечки",
        parse_mode="HTML",
    )


@router.message(Command("breach"))
async def breach_handler(message: Message):
    parts = message.text.split(maxsplit=1) if message.text else []

    if len(parts) < 2:
        await message.answer(
            "🔐 <b>Breach Check</b>\n\n"
            "Использование: <code>/breach email@example.com</code>",
            parse_mode="HTML",
        )
        return

    result = await check_email_breaches(parts[1].strip())
    await message.answer(
        format_breach_result(result),
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


@router.message(Command("ip"))
async def cmd_ip(message: Message):
    parts = message.text.split(maxsplit=1) if message.text else []

    if len(parts) < 2 or not parts[1].strip():
        await message.answer(
            "❗ Укажи IP-адрес.\n\n"
            "Пример:\n"
            "<code>/ip 8.8.8.8</code>",
            parse_mode="HTML",
        )
        return

    ip = parts[1].strip()

    await message.answer(
        f"🖥 Проверяю IP: <code>{ip}</code>\n"
        "Получаю публичную информацию...",
        parse_mode="HTML",
    )

    try:
        result = await analyze_ip(ip)

        await message.answer(
            format_ip_result(result),
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

    except Exception:
        logging.exception("IP OSINT error")
        await message.answer(
            "❌ Произошла ошибка при выполнении IP OSINT."
        )


@router.message(Command("domain"))
async def cmd_domain(message: Message):
    parts = message.text.split(maxsplit=1) if message.text else []

    if len(parts) < 2 or not parts[1].strip():
        await message.answer(
            "❗ Укажи домен.\n\n"
            "Пример:\n"
            "<code>/domain google.com</code>",
            parse_mode="HTML",
        )
        return

    domain = parts[1].strip()

    if len(domain) > 253:
        await message.answer("❗ Домен слишком длинный.")
        return

    await message.answer(
        f"🌐 Проверяю домен: <code>{domain}</code>\n"
        "Проверяю DNS и HTTP/HTTPS...",
        parse_mode="HTML",
    )

    try:
        result = await analyze_domain(domain)

        await message.answer(
            format_domain_result(result),
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

    except Exception:
        logging.exception("Domain OSINT error")
        await message.answer(
            "❌ Произошла ошибка при выполнении Domain OSINT."
        )


@router.message(Command("email"))
async def cmd_email(message: Message):
    parts = message.text.split(maxsplit=1) if message.text else []

    if len(parts) < 2 or not parts[1].strip():
        await message.answer(
            "❗ Укажи email.\n\n"
            "Пример:\n"
            "<code>/email test@gmail.com</code>",
            parse_mode="HTML",
        )
        return

    email = parts[1].strip()

    if len(email) > 320:
        await message.answer("❗ Email слишком длинный.")
        return

    await message.answer(
        f"📧 Проверяю email: <code>{email}</code>\n"
        "Проверяю формат и почтовую инфраструктуру домена...",
        parse_mode="HTML",
    )

    try:
        result = await analyze_email(email)

        await message.answer(
            format_email_result(result),
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

    except Exception:
        logging.exception("Email OSINT error")
        await message.answer(
            "❌ Произошла ошибка при выполнении Email OSINT."
        )


@router.message(Command("username"))
async def cmd_username(message: Message):
    parts = message.text.split(maxsplit=1) if message.text else []

    if len(parts) < 2 or not parts[1].strip():
        await message.answer(
            "❗ Укажи username.\n\n"
            "Пример:\n"
            "/username test"
        )
        return

    username = parts[1].strip()

    if len(username) > 100:
        await message.answer("❗ Username слишком длинный.")
        return

    await message.answer(
        f"🔎 Проверяю username: <code>{username}</code>\n"
        "Публичные источники проверяются параллельно...",
        parse_mode="HTML",
    )

    try:
        results = await search_username(username)
        report = format_results(results)

        await message.answer(
            f"🔎 <b>Username OSINT</b>\n\n"
            f"Username: <code>{username}</code>\n\n"
            f"{report}",
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

    except Exception:
        logging.exception("Username OSINT error")
        await message.answer(
            "❌ Произошла ошибка при выполнении Username OSINT."
        )


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode="HTML"),
    )
    dp = Dispatcher()

    dp.include_router(router)

    logging.info("OSINT Bot starting...")

    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
