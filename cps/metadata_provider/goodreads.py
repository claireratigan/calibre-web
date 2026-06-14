import datetime as dt
import html
import json
import os
import random
import re
import threading
import time
from collections import defaultdict
from concurrent.futures.thread import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional
from urllib.parse import quote

import bs4
from bs4 import BeautifulSoup
from bs4.element import ResultSet, Tag

from cps import logger
from cps.services.Metadata import Metadata, MetaRecord, MetaSourceInfo

log = logger.create()

SESSION_DIR = Path(os.path.expanduser("~/.goodreads_session"))
COOKIE_FILE = SESSION_DIR / "cookies.json"
USER_DATA_DIR = str(SESSION_DIR / "browser_profile")

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


def _is_waf_challenge(text: str) -> bool:
    return len(text) < 500 or (len(text) < 5000 and ("awsWaf" in text or "verify you are human" in text.lower()))


class GoodreadsSession:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._pw_lock = threading.Lock()
        self._browser_failed = False
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self._playwright = None
        self._browser = None
        self._page = None
        self._make_scraper()

    def _make_scraper(self):
        import cloudscraper
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )
        cookies = self._load_cookies()
        for c in cookies:
            if "goodreads.com" in c.get("domain", ""):
                try:
                    scraper.cookies.set(c["name"], c["value"], domain=c["domain"], path=c.get("path", "/"))
                except Exception:
                    pass
        self._scraper = scraper

    def _load_cookies(self) -> list:
        if COOKIE_FILE.exists():
            return json.loads(COOKIE_FILE.read_text())
        return []

    def _save_cookies(self, cookies: list):
        COOKIE_FILE.write_text(json.dumps(cookies, indent=2))

    def _try_cloudscraper(self, url: str, params: Optional[dict] = None) -> Optional[str]:
        headers = {
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self._scraper.headers.update(headers)
        try:
            resp = self._scraper.get(url, params=params, timeout=20)
            if resp.status_code == 200 and not _is_waf_challenge(resp.text):
                return resp.text
            log.debug("Goodreads WAF on %s (status=%d, len=%d)", url, resp.status_code, len(resp.text))
        except Exception:
            pass
        return None

    def _ensure_browser(self):
        if self._page is not None:
            return
        if self._browser_failed:
            return
        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch_persistent_context(
                user_data_dir=USER_DATA_DIR,
                headless=True,
                viewport={"width": 1280, "height": 800},
                locale="en-US",
                timezone_id="America/New_York",
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-automation",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            self._page = self._browser.new_page()
            self._page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                window.chrome = { runtime: { } };
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                const origQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
                window.navigator.permissions.query = (p) => (
                    p.name === 'notifications'
                        ? Promise.resolve({ state: 'denied' })
                        : origQuery(p)
                );
            """)
        except Exception as e:
            log.warning("Goodreads Playwright browser unavailable: %s", e)
            self._browser_failed = True

    def _refresh_waf_token(self) -> bool:
        self._ensure_browser()
        if self._page is None:
            log.warning("Goodreads: cannot refresh WAF token, browser unavailable")
            return False
        try:
            self._page.goto("https://www.goodreads.com/search?q=warmup", wait_until="load", timeout=30000)
            time.sleep(3)
        except Exception:
            pass
        try:
            cookies = self._page.context.cookies()
            self._save_cookies(cookies)
            self._make_scraper()
            return True
        except Exception:
            return False

    def fetch(self, url: str, params: Optional[dict] = None) -> str:
        text = self._try_cloudscraper(url, params)
        if text is not None:
            return text
        with self._pw_lock:
            text = self._try_cloudscraper(url, params)
            if text is not None:
                return text
            self._refresh_waf_token()
            text = self._try_cloudscraper(url, params)
            if text is not None:
                return text
            full_url = url
            if params:
                qs = "&".join(f"{k}={v}" for k, v in params.items())
                full_url = f"{url}?{qs}"
            if self._page:
                try:
                    self._page.goto(full_url, wait_until="load", timeout=30000)
                    time.sleep(5)
                except Exception:
                    pass
                return self._page.content()
            log.warning("Goodreads: all fetch paths exhausted for %s", url)
            return ""

    def fetch_soup(self, url: str, params: Optional[dict] = None) -> Optional[BeautifulSoup]:
        text = self.fetch(url, params)
        if not text:
            return None
        return BeautifulSoup(text, "html.parser")

    def close(self):
        with self._pw_lock:
            if self._browser:
                try:
                    self._browser.close()
                except Exception:
                    pass
            if self._playwright:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
            self._browser = None
            self._page = None
            self._playwright = None

# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#    Copyright (C) 2021 OzzieIsaacs
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.


class GoodReads(Metadata):
    __name__ = "GoodReads"
    __id__ = "goodreads"
    DESCRIPTION = "GoodReads"
    META_URL = "https://www.goodreads.com/"
    BOOK_URL = "https://www.goodreads.com/book/show/"
    SEARCH_URL = "https://www.goodreads.com/search?q="
    ISBN_TYPE = "ISBN_13"

    def search(
        self, query: str, generic_cover: str = "", locale: str = "en"
    ) -> Optional[List[MetaRecord]]:
        val = list()
        if self.active:
            title_tokens = list(self.get_title_tokens(query, strip_joiners=False))
            if title_tokens:
                tokens = [quote(t.encode("utf-8")) for t in title_tokens]
                query = html.escape(" ".join(tokens))
            session = GoodreadsSession()
            soup = session.fetch_soup(GoodReads.SEARCH_URL + query)
            if not soup:
                log.debug("Goodreads: no soup for q=%s", query)
                return []
            results: ResultSet = soup.find_all(
                "tr", dict(itemtype="http://schema.org/Book")
            )
            book_ids = [
                result.find("a", {"class": "bookTitle"})
                .get("href")
                .split("?", 1)[0]
                .removeprefix("/book/show/")
                for result in results
            ]
            if not book_ids:
                log.debug("Goodreads: no book IDs for q=%s", query)
                return []
            with ThreadPoolExecutor(max_workers=5) as executor:
                futs = [
                    executor.submit(GoodReads._parse_url, GoodReads.BOOK_URL + url)
                    for url in book_ids[:3]
                ]
                val = [fut.result() for fut in futs if fut.result() is not None]

        return val

    @staticmethod
    def _parse_url(url: str) -> Optional[MetaRecord]:
        session = GoodreadsSession()
        soup = session.fetch_soup(url)
        if not soup:
            return None
        script = soup.find("script", {"id": "__NEXT_DATA__"})
        if not script:
            log.warning("Goodreads: __NEXT_DATA__ missing in %s", url)
            return None
        metadata = json.loads(script.text)["props"]["pageProps"]["apolloState"]
        grouped_metadata = defaultdict(list)
        for k, v in metadata.items():
            if "__typename" in v:
                grouped_metadata[v["__typename"]].append(v)
        book = next((b for b in grouped_metadata["Book"] if "title" in b), None)
        if not book:
            return None
        return MetaRecord(
            id=url.split("/")[-1],
            title=book["title"],
            authors=[
                re.sub(r"\s{2,}", " ", contributor["name"])
                for contributor in grouped_metadata["Contributor"]
                if "name" in contributor
            ],
            url=url,
            source=MetaSourceInfo(
                id=GoodReads.__id__,
                description=GoodReads.DESCRIPTION,
                link=GoodReads.META_URL,
            ),
            cover=book["imageUrl"],
            description=book['description({"stripped":true})'],
            series=metadata[book["bookSeries"][0]["series"]["__ref"]]["title"]
            if book["bookSeries"]
            else None,
            series_index=int(book["bookSeries"][0]["userPosition"])
            if book["bookSeries"]
            and re.match(r"^\d+$", book["bookSeries"][0]["userPosition"])
            else None,
            identifiers={
                k: v
                for k, v in {
                    "goodreads": url.split("/")[-1],
                    "asin": book["details"]["asin"],
                    "isbn": book["details"]["isbn"],
                    "isbn13": book["details"]["isbn13"],
                }.items()
                if v
            },
            publisher=book["details"]["publisher"],
            publishedDate=dt.date.fromtimestamp(
                book["details"]["publicationTime"] // 1_000
            ).strftime("%Y-%m-%d")
            if book["details"]["publicationTime"] is not None
            else None,
            rating=round(grouped_metadata["Work"][0]["stats"]["averageRating"]),
            languages=[book["details"]["language"]["name"]],
            tags=[genre["genre"]["name"] for genre in book["bookGenres"]],
        )

    @staticmethod
    def _parse_search_result(
        result: Tag, generic_cover: str, locale: str
    ) -> MetaRecord:
        book_title = result.find("a", {"class": "bookTitle"})
        book_id = book_title.get("href").removeprefix("/book/show/").split("?", 1)[0]
        return MetaRecord(
            id=book_id,
            title=book_title.text.strip(),
            authors=[
                re.sub(r"\s+", " ", tag.find("span", {"itemprop": "name"}).text)
                for tag in result.find_all("div", {"class": "authorName__container"})
            ],
            url=GoodReads.BOOK_URL + book_id,
            source=MetaSourceInfo(
                id=GoodReads.__id__,
                description=GoodReads.DESCRIPTION,
                link=GoodReads.META_URL,
            ),
            cover=result.find("img", {"class": "bookCover"}).get("src"),
            rating=round(
                float(
                    re.search(
                        r"\d\.\d\d", result.find("span", {"class": "minirating"}).text
                    ).group(0)
                )
            ),
            identifiers=dict(goodreads=book_id),
        )
