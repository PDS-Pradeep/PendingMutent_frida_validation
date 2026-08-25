import requests
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin
from tqdm import tqdm
import csv
import time


# ============================================================
# CONFIGURATION
# ============================================================

BASE_URL = "https://apt.izzysoft.de/fdroid/"

# Repository IDs exactly as used by the IzzyOnDroid selector
REPOSITORIES = {
    "izzyondroid": "iod",
    "fdroid_main": "main",
    "fdroid_archive": "archive",
    "guardian": "guardian",
    "kali": "kali",
    "metatrans": "metatrans",
}

FILES_PER_REPO = 100

OUTPUT_DIR = Path("android_repositories")

HEADERS = {
    "User-Agent": "Mozilla/5.0 AndroidResearchDownloader/1.0"
}


# ============================================================
# CREATE SESSION
# ============================================================

session = requests.Session()
session.headers.update(HEADERS)


# ============================================================
# GET APK LINKS FROM ONE REPOSITORY PAGE
# ============================================================

def get_apk_links(repo_id):

    url = (
        BASE_URL
        + "index.php/list/page/1"
    )

    params = {
        "repo": repo_id,
        "limit": FILES_PER_REPO
    }

    print()
    print("=" * 80)
    print("Repository:", repo_id)
    print("Page:", url)
    print("Limit:", FILES_PER_REPO)
    print("=" * 80)

    response = session.get(
        url,
        params=params,
        timeout=120
    )

    print("HTTP:", response.status_code)

    response.raise_for_status()

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    apk_links = []

    # --------------------------------------------------------
    # Find all links ending with .apk
    # --------------------------------------------------------

    for link in soup.find_all("a", href=True):

        href = link["href"]

        if ".apk" not in href.lower():
            continue

        # Convert relative URL to absolute URL
        apk_url = urljoin(
            response.url,
            href
        )

        # Avoid duplicate APK links
        if apk_url not in apk_links:

            apk_links.append(
                apk_url
            )

    print(
        "APK links found:",
        len(apk_links)
    )

    return apk_links


# ============================================================
# DOWNLOAD ONE APK
# ============================================================

def download_apk(
    url,
    output_file
):

    if output_file.exists():

        print(
            "[SKIP]",
            output_file.name
        )

        return True

    print()
    print("Downloading:")
    print(url)

    try:

        response = session.get(
            url,
            stream=True,
            timeout=180
        )

        print(
            "HTTP:",
            response.status_code
        )

        if response.status_code != 200:

            print(
                "[FAILED]",
                response.status_code
            )

            return False

        # Reject error/listing pages that return HTTP 200 but are not
        # actually an APK (e.g. IzzyOnDroid returning an HTML page for a
        # broken/missing link). Check Content-Type first, then confirm
        # the body starts with the ZIP local file header magic bytes
        # (APKs are ZIP files, so they must start with "PK\x03\x04").
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" in content_type or "text/" in content_type:

            print(
                "[FAILED] Unexpected Content-Type:",
                content_type
            )

            return False

        total = int(
            response.headers.get(
                "Content-Length",
                0
            )
        )

        temp_file = output_file.with_suffix(
            ".apk.part"
        )

        first_chunk_checked = False

        with open(
            temp_file,
            "wb"
        ) as f:

            with tqdm(
                total=total,
                unit="B",
                unit_scale=True,
                desc=output_file.name
            ) as bar:

                for chunk in response.iter_content(
                    chunk_size=1024 * 1024
                ):

                    if chunk:

                        if not first_chunk_checked:

                            first_chunk_checked = True

                            if not chunk.startswith(b"PK\x03\x04"):

                                print(
                                    "[FAILED] Not a valid APK/ZIP "
                                    "(bad magic bytes) - got HTML/error "
                                    "response instead"
                                )

                                f.close()
                                temp_file.unlink()

                                return False

                        f.write(chunk)

                        bar.update(
                            len(chunk)
                        )

        # Rename only after successful download
        temp_file.rename(
            output_file
        )

        print(
            "[OK]",
            output_file.name
        )

        return True

    except Exception as e:

        print(
            "[ERROR]",
            e
        )

        temp_file = output_file.with_suffix(
            ".apk.part"
        )

        if temp_file.exists():
            temp_file.unlink()

        return False


# ============================================================
# PROCESS ONE REPOSITORY
# ============================================================

def process_repository(
    repo_name,
    repo_id
):

    print()
    print("#" * 80)
    print(
        "PROCESSING:",
        repo_name
    )
    print(
        "REPO ID:",
        repo_id
    )
    print("#" * 80)

    output_dir = (
        OUTPUT_DIR / repo_name
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Get APK URLs
    # --------------------------------------------------------

    try:

        apk_urls = get_apk_links(
            repo_id
        )

    except Exception as e:

        print(
            "[REPOSITORY ERROR]",
            e
        )

        return 0

    if not apk_urls:

        print(
            "[WARNING] No APKs found"
        )

        return 0

    # --------------------------------------------------------
    # Limit to requested number
    # --------------------------------------------------------

    apk_urls = apk_urls[
        :FILES_PER_REPO
    ]

    print()
    print(
        "Will download:",
        len(apk_urls)
    )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    metadata_file = (
        output_dir / "metadata.csv"
    )

    new_file = not metadata_file.exists()

    csv_file = open(
        metadata_file,
        "a",
        newline="",
        encoding="utf-8"
    )

    writer = csv.DictWriter(
        csv_file,
        fieldnames=[
            "repository",
            "repo_id",
            "apk_name",
            "url"
        ]
    )

    if new_file:

        writer.writeheader()

    # --------------------------------------------------------
    # Download
    # --------------------------------------------------------

    downloaded = 0

    for number, apk_url in enumerate(
        apk_urls,
        start=1
    ):

        # Get filename from URL
        apk_name = (
            apk_url
            .split("/")[-1]
            .split("?")[0]
        )

        if not apk_name.lower().endswith(
            ".apk"
        ):
            continue

        print()
        print(
            f"[{number}/{len(apk_urls)}]"
        )

        output_file = (
            output_dir / apk_name
        )

        success = download_apk(
            apk_url,
            output_file
        )

        if success:

            writer.writerow({

                "repository":
                    repo_name,

                "repo_id":
                    repo_id,

                "apk_name":
                    apk_name,

                "url":
                    apk_url
            })

            csv_file.flush()

            downloaded += 1

        # Small delay between requests
        time.sleep(0.2)

    csv_file.close()

    print()
    print("-" * 80)
    print(
        repo_name,
        "DONE"
    )
    print(
        "Downloaded:",
        downloaded
    )
    print("-" * 80)

    return downloaded


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    total = 0

    for repo_name, repo_id in REPOSITORIES.items():

        count = process_repository(
            repo_name,
            repo_id
        )

        total += count

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("ALL REPOSITORIES COMPLETED")
    print("=" * 80)

    print(
        "Repositories:",
        len(REPOSITORIES)
    )

    print(
        "Requested per repository:",
        FILES_PER_REPO
    )

    print(
        "Total APKs downloaded:",
        total
    )

    print(
        "Output directory:",
        OUTPUT_DIR
    )


if __name__ == "__main__":
    main()