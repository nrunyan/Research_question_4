#!/usr/bin/env python3
"""
Compare CAPTCHA / bot-challenge rates for normal vs Tor connections.

Input:  tranco_categorized.csv (from categorize_tranco.py)
Output: results.jsonl (incremental, resumable), summary.json, screenshots/

Detection is layered, strongest evidence first:
  1. Response headers   (cf-mitigated: challenge, x-datadome)
  2. Network requests   (recaptcha, hcaptcha, turnstile, arkose, datadome, ...)
  3. DOM                (widget iframes / containers, and whether they're visible)
  4. Page title + short, specific text phrases (weak, only used with other evidence)

Each page gets one captcha_type:
  challenge_page      full interstitial / block page (Cloudflare "Just a moment", etc.)
  captcha_widget      a visible captcha widget on the page (login form, etc.)
  captcha_script_only provider scripts loaded but nothing visible (invisible/v3)
  possible            weak text evidence only
  none

captcha_detected is True for challenge_page and captcha_widget.

Usage:
    python captcha_detector.py --input tranco_categorized.csv \
        --categories financial social --limit 50
"""
import argparse
import asyncio
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import Error as PWError
from playwright.async_api import async_playwright

TOR_PROXY = {"server": "socks5://127.0.0.1:9050"}


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
CONTEXT_OPTS = dict(
    user_agent=USER_AGENT,
    viewport={"width": 1366, "height": 768},
    locale="en-US",
    timezone_id="America/New_York",
)
LAUNCH_ARGS = ["--disable-blink-features=AutomationControlled"]


NETWORK_SIGNATURES = {
    "recaptcha": ["google.com/recaptcha", "gstatic.com/recaptcha", "recaptcha.net"],
    "hcaptcha": ["hcaptcha.com"],
    "turnstile": ["challenges.cloudflare.com/turnstile"],
    "cloudflare_challenge": ["/cdn-cgi/challenge-platform", "challenges.cloudflare.com"],
    "arkose": ["arkoselabs.com", "funcaptcha.com"],
    "geetest": ["geetest.com", "geetest.cn"],
    "datadome": ["captcha-delivery.com", "datadome.co"],
    "perimeterx": ["perimeterx.net", "px-cdn.net", "px-cloud.net", "/px/captcha"],
    "imperva": ["_incapsula_resource"],
    "aws_waf": ["awswaf.com"],
    "friendly_captcha": ["friendlycaptcha.com"],
    "mtcaptcha": ["mtcaptcha.com"],
}


DOM_SELECTORS = {
    "recaptcha": ["iframe[src*='recaptcha']", ".g-recaptcha", "#recaptcha"],
    "hcaptcha": ["iframe[src*='hcaptcha']", ".h-captcha"],
    "turnstile": [".cf-turnstile", "iframe[src*='challenges.cloudflare.com']"],
    "cloudflare_challenge": ["#challenge-form", "#cf-challenge-running",
                             "#challenge-running", "#challenge-stage"],
    "arkose": ["iframe[src*='arkoselabs']", "#funcaptcha"],
    "geetest": [".geetest_holder", ".geetest_panel"],
    "datadome": ["iframe[src*='captcha-delivery.com']"],
    "perimeterx": ["#px-captcha"],
    "imperva": ["iframe[src*='_Incapsula_Resource']"],
    "aws_waf": ["#aws-waf-captcha", "awswaf-captcha"],
}


BLOCK_TITLES = [
    "just a moment", "attention required", "access denied", "are you a robot",
    "verify you are human", "pardon our interruption", "security check",
    "robot check", "human verification", "checking your browser",
    "one more step", "request blocked",
]


CHALLENGE_PHRASES = [
    "verify you are human", "verify you are a human", "unusual traffic",
    "are you a robot", "i'm not a robot", "checking your browser",
    "press & hold", "press and hold", "complete the security check",
    "select all images", "select both images", "needs to review the security",
    "enable javascript and cookies to continue", "automated queries",
    "confirm you are a human", "prove you are human",
]


def now():
    return datetime.now(timezone.utc).isoformat()


def classify(status, headers, title, text, net_providers, dom_visible, dom_present):
    """Turn raw evidence into (captcha_type, providers, signals)."""
    signals = []
    title_l = (title or "").lower()
    text_l = (text or "").lower()
    short_page = len(text_l) < 1500

    if headers.get("cf-mitigated", "").lower() == "challenge":
        signals.append("header:cf-mitigated=challenge")
    if "x-datadome" in headers and status in (403, 429):
        signals.append("header:x-datadome")
    hard_header = any(s.startswith("header:") for s in signals)

    title_hits = [t for t in BLOCK_TITLES if t in title_l]
    signals += [f"title:{t}" for t in title_hits]

    phrase_hits = [p for p in CHALLENGE_PHRASES if p in text_l]
    signals += [f"text:{p}" for p in phrase_hits]

    providers = sorted(set(net_providers) | set(dom_present))
    signals += [f"network:{p}" for p in sorted(net_providers)]
    signals += [f"dom:{p}" for p in sorted(dom_present)]
    if dom_visible:
        signals.append("dom_visible:" + ",".join(sorted(dom_visible)))

    interstitial = (
        hard_header
        or (title_hits and (status >= 400 or short_page))
        or (phrase_hits and short_page)
        or ("cloudflare_challenge" in dom_present)
    )

    if interstitial:
        ctype = "challenge_page"
    elif dom_visible:
        ctype = "captcha_widget"
    elif providers:
        ctype = "captcha_script_only"
    elif phrase_hits or title_hits:
        ctype = "possible"
    else:
        ctype = "none"
    return ctype, providers, signals


async def any_visible(page, selector):
    try:
        loc = page.locator(selector)
        for i in range(min(await loc.count(), 5)):
            if await loc.nth(i).is_visible():
                return True
    except PWError:
        pass
    return False


async def attempt(browser, url, condition, timeout_ms, shots_dir):
    context = await browser.new_context(**CONTEXT_OPTS)
    page = await context.new_page()
    request_urls = []
    page.on("request", lambda r: request_urls.append(r.url))

    result = {
        "url": url, "condition": condition, "timestamp": now(),
        "captcha_detected": False, "captcha_type": None, "providers": [],
        "signals": [], "status_code": None, "title": None,
        "final_url": None, "error": None,
    }
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        headers = {}
        if resp:
            result["status_code"] = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}

        # Let challenges/widgets render, but don't hang on chatty sites.
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except PWError:
            pass
        await page.wait_for_timeout(2000)

        result["title"] = await page.title()
        result["final_url"] = page.url
        try:
            text = await page.locator("body").inner_text(timeout=5000)
        except PWError:
            text = ""

        net = set()
        for u in request_urls:
            ul = u.lower()
            for prov, needles in NETWORK_SIGNATURES.items():
                if any(n in ul for n in needles):
                    net.add(prov)

        dom_present, dom_visible = set(), set()
        for prov, selectors in DOM_SELECTORS.items():
            for sel in selectors:
                if await page.locator(sel).count() > 0:
                    dom_present.add(prov)
                    if await any_visible(page, sel):
                        dom_visible.add(prov)

        ctype, providers, signals = classify(
            result["status_code"] or 0, headers, result["title"], text,
            net, dom_visible, dom_present)

        result.update(captcha_type=ctype, providers=providers, signals=signals,
                      captcha_detected=ctype in ("challenge_page", "captcha_widget"))

        if ctype != "none":
            shots_dir.mkdir(parents=True, exist_ok=True)
            name = hashlib.sha1(url.encode()).hexdigest()[:12]
            await page.screenshot(path=str(shots_dir / f"{condition}_{name}.png"))
    except Exception as e:  # noqa: BLE001 - record any failure, keep scanning
        result["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        await context.close()
    return result


async def check_site(browser, rec, condition, timeout_ms, shots_dir):
    domain = rec["domain"]
    urls = [f"https://{domain}"]
    if not domain.startswith("www."):
        urls.append(f"https://www.{domain}")

    result = None
    for url in urls:
        result = await attempt(browser, url, condition, timeout_ms, shots_dir)
        if result["error"] is None:
            break
    result.update(domain=domain, rank=int(rec["rank"]), category=rec["category"])
    return result


async def verify_tor(browser):
    ctx = await browser.new_context()
    page = await ctx.new_page()
    try:
        await page.goto("https://check.torproject.org/api/ip", timeout=60000)
        data = json.loads(await page.locator("body").inner_text())
        return bool(data.get("IsTor")), data.get("IP")
    except Exception:  # noqa: BLE001
        return False, None
    finally:
        await ctx.close()


def load_records(args):
    skip = set() if args.include_infra else {"infrastructure"}
    wanted = set(args.categories) if args.categories else None
    recs = []
    with open(args.input, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["category"] in skip:
                continue
            if wanted and row["category"] not in wanted:
                continue
            recs.append(row)
    return recs[: args.limit] if args.limit else recs


def load_done(path):
    done = set()
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("error") is None:  # re-try failures on resume
                done.add((r["domain"], r["condition"]))
    return done


def summarize(path):
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    by_cond = defaultdict(list)
    for r in rows:
        by_cond[r["condition"]].append(r)

    summary = {"totals": {}, "by_category": {}, "tor_only": [], "providers": {}}
    for cond, rs in by_cond.items():
        ok = [r for r in rs if r["error"] is None]
        det = [r for r in ok if r["captcha_detected"]]
        summary["totals"][cond] = {
            "sites": len(rs), "loaded": len(ok), "errors": len(rs) - len(ok),
            "captcha_detected": len(det),
            "rate": round(len(det) / len(ok), 4) if ok else None,
            "types": dict(Counter(r["captcha_type"] for r in ok)),
        }
        summary["providers"][cond] = dict(
            Counter(p for r in det for p in r["providers"]))

    cats = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # cat -> cond -> [hit, ok]
    for r in rows:
        if r["error"] is None:
            c = cats[r["category"]][r["condition"]]
            c[1] += 1
            c[0] += r["captcha_detected"]
    summary["by_category"] = {
        cat: {cond: {"detected": h, "loaded": n,
                     "rate": round(h / n, 4) if n else None}
              for cond, (h, n) in conds.items()}
        for cat, conds in cats.items()}

    by_domain = defaultdict(dict)
    for r in rows:
        if r["error"] is None:
            by_domain[r["domain"]][r["condition"]] = r["captcha_detected"]
    summary["tor_only"] = sorted(
        d for d, c in by_domain.items() if c.get("tor") and not c.get("normal"))
    return summary


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="tranco_categorized.csv")
    ap.add_argument("--out", default="results.jsonl")
    ap.add_argument("--categories", nargs="*", help="e.g. financial social")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--include-infra", action="store_true",
                    help="also scan CDN/ad/DNS domains (usually pointless)")
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--tor-concurrency", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=30, help="seconds (normal)")
    ap.add_argument("--tor-timeout", type=int, default=60, help="seconds (tor)")
    ap.add_argument("--no-tor", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    shots = Path("screenshots")
    records = load_records(args)
    done = load_done(out)
    print(f"{len(records)} sites selected, {len(done)} (site, condition) pairs already done")

    lock = asyncio.Lock()
    counts = Counter()

    async def worker(browser, rec, cond, sem, timeout_s):
        if (rec["domain"], cond) in done:
            return
        async with sem:
            r = await check_site(browser, rec, cond, timeout_s * 1000, shots)
        async with lock:
            with open(out, "a") as f:
                f.write(json.dumps(r) + "\n")
            counts[cond] += 1
            flag = r["captcha_type"] if not r["error"] else f"ERR {r['error'][:50]}"
            print(f"[{cond:>6}] {counts[cond]:>4} {rec['domain']:<30} {flag}")

    async with async_playwright() as p:
        normal = await p.chromium.launch(args=LAUNCH_ARGS)
        tor = None
        if not args.no_tor:
            tor = await p.chromium.launch(args=LAUNCH_ARGS, proxy=TOR_PROXY)
            is_tor, ip = await verify_tor(tor)
            if not is_tor:
                raise SystemExit("Tor check failed: is Tor running on 127.0.0.1:9050?")
            print(f"Tor OK (exit IP {ip})")

        n_sem = asyncio.Semaphore(args.concurrency)
        t_sem = asyncio.Semaphore(args.tor_concurrency)
        tasks = [worker(normal, r, "normal", n_sem, args.timeout) for r in records]
        if tor:
            tasks += [worker(tor, r, "tor", t_sem, args.tor_timeout) for r in records]
        await asyncio.gather(*tasks)

        await normal.close()
        if tor:
            await tor.close()

    summary = summarize(out)
    Path("summary.json").write_text(json.dumps(summary, indent=2))
    print("\n=== Summary ===")
    for cond, t in summary["totals"].items():
        print(f"{cond:>6}: {t['captcha_detected']}/{t['loaded']} captcha "
              f"({t['rate']}), {t['errors']} errors, types={t['types']}")
    print(f"Captcha on Tor but not normal: {len(summary['tor_only'])} sites")
    print("Full breakdown in summary.json")


if __name__ == "__main__":
    asyncio.run(main())