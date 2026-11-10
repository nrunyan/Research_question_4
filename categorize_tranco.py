#!/usr/bin/env python3
"""
Read the Tranco list (CSV: rank,domain), take the top N, and sort each domain
into a category (financial, social, search, ...).

Download the list from https://tranco-list.eu (the "top-1m.csv" inside the zip).

Categorization works in three layers, strongest first:
  1. Known-domain table below (exact / parent-domain match)
  2. TLD rules (.gov -> government, .edu -> education)
  3. Keyword heuristics (low confidence, labelled method="heuristic")
Anything left is "uncategorized" and written to uncategorized.txt so you can
add it to KNOWN or to an overrides file (--overrides overrides.json, a plain
{"domain.com": "category"} mapping).

Usage:
    python categorize_tranco.py --input top-1m.csv --limit 1000
"""
import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

KNOWN = {
    "financial": """
        paypal.com stripe.com chase.com bankofamerica.com wellsfargo.com citi.com
        capitalone.com americanexpress.com visa.com mastercard.com coinbase.com
        binance.com kraken.com robinhood.com schwab.com fidelity.com vanguard.com
        intuit.com wise.com revolut.com bloomberg.com investing.com marketwatch.com
        nasdaq.com blockchain.com coindesk.com coinmarketcap.com coingecko.com
        squareup.com venmo.com cash.app hsbc.com barclays.co.uk santander.com
        ing.com alipay.com paytm.com razorpay.com adyen.com klarna.com usbank.com
        pnc.com ally.com sofi.com etrade.com tradingview.com tdbank.com
        creditkarma.com nerdwallet.com morningstar.com payoneer.com skrill.com
    """,
    "social": """
        facebook.com instagram.com twitter.com x.com linkedin.com reddit.com
        tiktok.com pinterest.com snapchat.com tumblr.com discord.com telegram.org
        t.me whatsapp.com weibo.com vk.com quora.com threads.net bsky.app line.me
        wechat.com qq.com medium.com flickr.com meetup.com nextdoor.com
        mastodon.social ok.ru douyin.com kuaishou.com
    """,
    "search": """
        google.com bing.com yahoo.com duckduckgo.com baidu.com yandex.ru yandex.com
        ecosia.org naver.com sogou.com ask.com startpage.com
    """,
    "ecommerce": """
        amazon.com ebay.com aliexpress.com alibaba.com walmart.com target.com
        etsy.com shopify.com bestbuy.com taobao.com jd.com temu.com shein.com
        rakuten.co.jp mercadolibre.com flipkart.com homedepot.com ikea.com
        costco.com wayfair.com zalando.com lowes.com tmall.com pinduoduo.com
        amazon.co.uk amazon.de amazon.co.jp amazon.in
    """,
    "news": """
        nytimes.com bbc.com bbc.co.uk cnn.com theguardian.com washingtonpost.com
        forbes.com reuters.com foxnews.com nbcnews.com apnews.com huffpost.com
        wsj.com buzzfeed.com dailymail.co.uk independent.co.uk usatoday.com
        cnbc.com npr.org time.com theverge.com techcrunch.com wired.com
        businessinsider.com bloomberg.net
    """,
    "streaming_media": """
        youtube.com netflix.com twitch.tv spotify.com hulu.com disneyplus.com
        primevideo.com soundcloud.com vimeo.com imdb.com dailymotion.com
        bilibili.com max.com hbomax.com crunchyroll.com pandora.com deezer.com
        tidal.com
    """,
    "tech_software": """
        microsoft.com apple.com github.com stackoverflow.com stackexchange.com
        gitlab.com cloudflare.com mozilla.org oracle.com ibm.com adobe.com
        salesforce.com atlassian.com slack.com zoom.us dropbox.com notion.so
        openai.com anthropic.com nvidia.com intel.com samsung.com wordpress.com
        wordpress.org w3.org npmjs.com python.org docker.com ubuntu.com
        godaddy.com namecheap.com squarespace.com wix.com weebly.com
        sourceforge.net canva.com figma.com
    """,
    "email_communication": """
        outlook.com live.com office.com proton.me protonmail.com zoho.com mail.ru
        icloud.com skype.com gmail.com
    """,
    "reference_education": """
        wikipedia.org wikimedia.org archive.org britannica.com wikihow.com
        fandom.com w3schools.com coursera.org udemy.com khanacademy.org edx.org
        duolingo.com
    """,
    "travel": """
        booking.com tripadvisor.com expedia.com airbnb.com kayak.com skyscanner.com
        agoda.com hotels.com trip.com uber.com
    """,
    "gaming": """
        steampowered.com steamcommunity.com epicgames.com roblox.com ea.com
        xbox.com playstation.com blizzard.com riotgames.com minecraft.net
        nintendo.com itch.io ubisoft.com
    """,
    # Mostly non-browsable domains (CDNs, ad/tracking, DNS). Tranco ranks these
    # high because it counts DNS/traffic popularity, so they're skipped by the
    # detector by default.
    "infrastructure": """
        googleapis.com gstatic.com googleusercontent.com akamaiedge.net akamai.net
        akamaihd.net cloudfront.net amazonaws.com azureedge.net windows.net
        doubleclick.net googlesyndication.com googletagmanager.com
        google-analytics.com facebook.net fbcdn.net cdninstagram.com twimg.com
        ytimg.com fastly.net cloudflare.net cloudflare-dns.com root-servers.net
        a2z.com apple-dns.net icloud-content.com ampproject.org jsdelivr.net
        unpkg.com scorecardresearch.com adnxs.com criteo.com taboola.com
        outbrain.com demdex.net msftncsi.com office.net microsoftonline.com
        trafficmanager.net akadns.net edgekey.net edgesuite.net
    """,
}

DOMAIN_TO_CAT = {d: cat for cat, blob in KNOWN.items() for d in blob.split()}

GOV_RE = re.compile(r"\.(gov|mil)(\.[a-z]{2})?$|\.gob\.|\.gouv\.")
EDU_RE = re.compile(r"\.(edu|ac)(\.[a-z]{2})?$")

HEURISTICS = [
    ("financial", ("bank", "financ", "crypto", "coin", "invest", "loan",
                   "insurance", "trading", "credit", "wallet")),
    ("news", ("news", "gazette", "tribune", "herald")),
    ("ecommerce", ("shop", "store", "mall", "buy", "market")),
    ("gaming", ("game", "gaming")),
    ("travel", ("travel", "hotel", "flight", "airline")),
    ("streaming_media", ("tube", "stream", "video", "music", "radio")),
    ("infrastructure", ("cdn", "dns", "akam", "static", "analytics", "tracker",
                        "edge", "pixel")),
]


def categorize(domain, overrides):
    d = domain.lower()
    if d in overrides:
        return overrides[d], "override"

    parts = d.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in overrides:
            return overrides[cand], "override"
        if cand in DOMAIN_TO_CAT:
            return DOMAIN_TO_CAT[cand], "known"

    if GOV_RE.search(d):
        return "government", "tld"
    if EDU_RE.search(d):
        return "education", "tld"

    # Heuristics only look at the first label so "tld" noise doesn't match.
    label = parts[0]
    for cat, needles in HEURISTICS:
        if any(n in label for n in needles):
            return cat, "heuristic"

    return "uncategorized", "none"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="top-1m.csv", help="Tranco CSV (rank,domain)")
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--overrides", help="JSON file {domain: category}")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    overrides = {}
    if args.overrides:
        overrides = {k.lower(): v for k, v in
                     json.loads(Path(args.overrides).read_text()).items()}

    rows = []
    with open(args.input, newline="", encoding="utf-8") as f:
        for rec in csv.reader(f):
            if len(rec) < 2 or not rec[0].strip().isdigit():
                continue  # skip header / junk
            rank, domain = int(rec[0]), rec[1].strip().lower()
            rows.append((rank, domain))
            if len(rows) >= args.limit:
                break

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    grouped = defaultdict(list)
    classified = []
    for rank, domain in rows:
        cat, method = categorize(domain, overrides)
        classified.append({"rank": rank, "domain": domain,
                           "category": cat, "method": method})
        grouped[cat].append({"rank": rank, "domain": domain})

    with open(outdir / "tranco_categorized.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rank", "domain", "category", "method"])
        w.writeheader()
        w.writerows(classified)

    (outdir / "tranco_by_category.json").write_text(
        json.dumps(grouped, indent=2, sort_keys=True))

    (outdir / "uncategorized.txt").write_text(
        "\n".join(r["domain"] for r in classified if r["category"] == "uncategorized"))

    print(f"Categorized {len(classified)} domains:")
    for cat, items in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        print(f"  {cat:<22}{len(items):>5}")
    print("\nReview uncategorized.txt and add entries to KNOWN or an overrides file.")


if __name__ == "__main__":
    main()