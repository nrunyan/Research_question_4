
import asyncio
import json
from datetime import datetime, timezone

from playwright.async_api import async_playwright

WEBSITES = [
    "https://playwright.dev/",
    "https://www.wikipedia.org",
    "https://www.reddit.com",
]

TOR_PROXY = {
    "server": "socks5://127.0.0.1:9050"
}

#TODO: add reall indicators
CAPTCHA_INDICATORS = [
    "captcha",
    "verify you are human",
    "unusual traffic",
    "security challenge",
    "are you a robot",
    "cf-challenge",
    "challenge-platform",
]

async def check_website(browser, url, condition):
    context = await browser.new_context()
    page = await context.new_page()

    result = {
        "url": url,
        "condition": condition,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "captcha_detected": False,
        "status_code": None,
        "title": None,
        "error": None,
    }

    try:
        response = await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=30000
        )

        if response:
            result["status_code"] = response.status

        await page.wait_for_timeout(3000)

        result["title"] = await page.title()

        text = await page.locator("body").inner_text(
            timeout=5000
        )

        text = text.lower()

        result["captcha_detected"] = any(
            indicator in text
            for indicator in CAPTCHA_INDICATORS
        )

        if result["captcha_detected"]:
            filename = (
                f"screenshot_{condition}_"
                f"{abs(hash(url))}.png"
            )
            await page.screenshot(path=filename)

    except Exception as e:
        result["error"] = str(e)

    finally:
        await context.close()

    return result

async def main():
    async with async_playwright() as p:
        normal_browser = await p.chromium.launch()
        tor_browser = await p.chromium.launch(
            proxy=TOR_PROXY
        )
        results = []

        for url in WEBSITES:

            normal = await check_website(
                normal_browser, url, "normal"
            )

            tor = await check_website(
                tor_browser, url, "tor"
            )
            results.extend([normal, tor])
            await asyncio.sleep(10)

        with open("results.json", "w") as f:
            json.dump(results, f, indent=4)

        await normal_browser.close()
        await tor_browser.close()

if __name__ == "__main__":
    asyncio.run(main())