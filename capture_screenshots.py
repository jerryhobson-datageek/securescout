# -*- coding: utf-8 -*-
import sys, os, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

URL  = "https://security.newtekk.com"
PASS = "Vzwdata@1977"
OUT  = r"C:\claudcode\securescout\docs\screenshots"
os.makedirs(OUT, exist_ok=True)

def ss(page, name):
    p = os.path.join(OUT, name)
    page.screenshot(path=p, full_page=False)
    print(f"  saved: {name}")

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 900})

    # ── Login screen ──────────────────────────────────────────────────────────
    page.goto(URL)
    page.wait_for_selector("#authScreen.show", timeout=10000)
    time.sleep(0.5)
    ss(page, "01_login.png")
    print("Login screen captured")

    # ── Log in ────────────────────────────────────────────────────────────────
    page.fill("#authPassword", PASS)
    page.click("#authBtn")
    page.wait_for_selector("#app.show", timeout=10000)
    # Wait for scan results to populate
    page.wait_for_selector(".badge-ok, .badge-warn, .badge-fail", timeout=30000)
    time.sleep(2)

    # ── Main dashboard ────────────────────────────────────────────────────────
    ss(page, "02_dashboard.png")
    print("Dashboard captured")

    # ── Fix recommendation expanded ───────────────────────────────────────────
    # Click the first "▸ fix" toggle on any card
    fix_toggle = page.query_selector(".fix-toggle")
    if fix_toggle:
        fix_toggle.scroll_into_view_if_needed()
        fix_toggle.click()
        time.sleep(0.4)
        # Scroll so the fix block is visible
        fix_block = page.query_selector(".fix-block.open")
        if fix_block:
            fix_block.scroll_into_view_if_needed()
            time.sleep(0.3)
        ss(page, "03_fix_recommendation.png")
        print("Fix recommendation captured")

    # ── Add Site modal ────────────────────────────────────────────────────────
    page.evaluate("window.scrollTo(0, 0)")
    time.sleep(0.2)
    page.click("button:has-text('+ Add Site')")
    page.wait_for_selector("#addModal.open", timeout=5000)
    time.sleep(0.3)
    ss(page, "04_add_site_modal.png")
    print("Add site modal captured")
    page.keyboard.press("Escape")

    # ── Full dashboard scroll (cards visible) ─────────────────────────────────
    page.evaluate("window.scrollTo(0, 0)")
    time.sleep(0.3)
    page.screenshot(path=os.path.join(OUT, "05_dashboard_full.png"), full_page=True)
    print("  saved: 05_dashboard_full.png")

    browser.close()
    print("\nAll screenshots saved to docs/screenshots/")
