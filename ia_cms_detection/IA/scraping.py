import httpx
import asyncio
import os
import pandas as pd
from bs4 import BeautifulSoup
from tqdm.asyncio import tqdm_asyncio
import time

headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

semaphore = asyncio.Semaphore(100)

def _read_default_timeout() -> float:
    raw = os.environ.get("SCAN_HTTP_TIMEOUT")
    if not raw:
        return 45.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 45.0

HTTP_TIMEOUT_SECONDS = _read_default_timeout()

async def fetch_html(url, retries=2):
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS)
    for _ in range(retries):
        try:
            async with semaphore:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
                    response = await client.get(url)
                    try:
                        robots_response = await client.get(url.rstrip("/") + "/robots.txt")
                        robots_txt = robots_response.text.lower()
                    except:
                        robots_txt = ""
                    return url, response.text.lower(), response.headers, robots_txt
        except Exception as e:
            print(f"❌ Erreur sur {url}: {type(e).__name__} – {e}")
            await asyncio.sleep(1)
    return url, "", {}, ""

async def scrape_sites(urls):
    tasks = [fetch_html(url) for url in urls]
    results = []
    for coro in tqdm_asyncio.as_completed(tasks, total=len(tasks), desc="🔎 Scraping en cours"):
        result = await coro
        print(f"✅ Fini : {result[0]}")
        results.append(result)
    return {url: (html, headers, robots) for url, html, headers, robots in results}

def extract_features(url, html, headers, robots):
    soup = BeautifulSoup(html, "html.parser")
    meta_generator = soup.find("meta", attrs={"name": "generator"})
    meta_content = meta_generator["content"].lower() if meta_generator and "content" in meta_generator.attrs else ""

    wp_signatures = [
        "wpApiSettings", "wp-block-", "editor-post-title", "data-wp",
        "wp-embed", "/wp-json/wp/v2", "/?rest_route="
    ]
    wp_signature_found = any(sig in html for sig in wp_signatures)

    features = {
        "url": url,
        "has_wp_content": int("/wp-content/" in html),
        "has_wp_includes": int("/wp-includes/" in html),
        "has_wp_meta": int("wordpress" in meta_content),
        "has_wp_json": int("/wp-json/" in html),
        "has_wp_xmlrpc": int("/xmlrpc.php" in html),
        "has_wp_comment": int("<!-- This is WordPress -->" in html),
        "has_wp_header": int("x-powered-by" in headers and "wordpress" in headers.get("x-powered-by", "").lower()),
        "has_wp_robots": int("wp-admin" in robots),
        "has_wp_login": int("/wp-login.php" in html),
        "has_wp_admin_bar": int("wp-admin-bar" in html),
        "has_wp_generator_meta": int('content="wordpress' in html),
        "has_readme_html": int("/readme.html" in html),
        "has_wp_advanced": int(wp_signature_found),
        "has_wp_login_url": int(any("/wp-login.php" in a.get("href", "") for a in soup.find_all("a"))),
        "has_wp_admin_url": int(any("/wp-admin/" in a.get("href", "") for a in soup.find_all("a"))),
        "has_wp_plugins_dir": int("/wp-content/plugins/" in html),
        "has_wp_themes_dir": int("/wp-content/themes/" in html),
        "has_wp_rest_api": int("wp/v2/" in html),
        "has_wp_nonce": int("wp_nonce" in html),

        "has_prestashop": int("/themes/classic/" in html or "prestashop" in html or "var prestashop" in html),
        "has_prestashop_object": int("prestashopobject" in html.lower()),
        "has_prestashop_data": int("data-prestashop" in html.lower()),
        "has_prestashop_config": int("config/settings.inc.php" in html),
        "has_prestashop_meta": int("prestashop" in meta_content),
        "has_prestashop_js": int("prestashop.js" in html),
        "has_prestashop_modules": int("/modules/" in html),
        "has_prestashop_classes": int("/classes/" in html),
        "has_prestashop_controllers": int("/controllers/" in html),
        "has_prestashop_cookie": int("set-cookie" in headers and "prestashop" in headers.get("set-cookie", "").lower()),
        "has_ps_admin_dir": int("/admin" in html),
        "has_ps_js_object": int("prestashop.blockcart" in html or "prestashop" in html),
        "has_ps_language_block": int("language-selector" in html),
        "has_ps_ajax_controller": int("ajax.php" in html),

        "has_drupal": int("/sites/default/files/" in html or "drupal" in html),
        "has_drupal_js": int("drupal.js" in html),
        "has_drupal_meta": int("drupal" in meta_content),
        "has_drupal_theme": int("drupal-theme" in html),
        "has_drupal_core": int("/core/" in html),
        "has_drupal_robots": int("/core/" in robots),
        "has_drupal_header": int("x-drupal-cache" in headers or ("x-generator" in headers and "drupal" in headers.get("x-generator", "").lower())),
        "has_drupal_views": int("views-exposed-form" in html or "views-row" in html),
        "has_drupal_toolbar": int("toolbar-menu" in html),
        "has_drupal_settings": int("drupalSettings =" in html),
        "has_drupal_ajax": int("drupal_ajax" in html),
    }

    return features

def rule_based_detection(row):
    if row["has_wp_content"] or row["has_wp_meta"] or row["has_wp_advanced"]:
        return "WordPress"
    elif row["has_prestashop_meta"] or row["has_prestashop"] or row["has_ps_js_object"]:
        return "PrestaShop"
    elif row["has_drupal_meta"] or row["has_drupal"] or row["has_drupal_core"]:
        return "Drupal"
    else:
        return "Unknown"

async def main():
    start = time.time()
    input_file = "ia_cms_detection/IA/cms_connus.csv"
    df_input = pd.read_csv(input_file)

    df_input['URL'] = df_input['URL'].str.lstrip('.')
    df_input['URL'] = df_input['URL'].apply(
        lambda x: x if x.startswith(('http://', 'https://')) else 'http://' + x
    )

    urls = df_input["URL"].dropna().tolist()
    scraped_data = await scrape_sites(urls)

    extracted = [extract_features(url, html, headers, robots) for url, (html, headers, robots) in scraped_data.items()]
    df_features = pd.DataFrame(extracted)

    # Ajout de la prédiction rule-based
    df_features["cms_detect"] = df_features.apply(rule_based_detection, axis=1)

    # Fusion CMS connu
    df_final = df_features.merge(df_input, left_on="url", right_on="URL", how="left")
    df_final.drop(columns=["url"], inplace=True)

    df_final.to_csv("dataset_training.csv", index=False)

    print("✅ Dataset généré : dataset_training.csv")
    print(f"⏱️ Temps total : {round((time.time() - start) / 60, 2)} minutes")

if __name__ == "__main__":
    asyncio.run(main())
