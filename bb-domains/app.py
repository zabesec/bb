import datetime
import os
import time

import requests
from dotenv import load_dotenv

print(f"[{datetime.datetime.now()}] bb-domains has been started")

load_dotenv()
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
LOCAL_FILE = "domains.txt"
URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/domains.txt"


def fetch_remote():
    r = requests.get(URL)
    return r.text.strip().splitlines()


def fetch_local():
    if not os.path.exists(LOCAL_FILE):
        return []
    with open(LOCAL_FILE, "r") as f:
        return f.read().strip().splitlines()


def save_local(data):
    with open(LOCAL_FILE, "w") as f:
        f.write("\n".join(data))


def create_gist(content, filename, description):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    data = {
        "description": description,
        "public": False,
        "files": {filename: {"content": content}},
    }
    r = requests.post("https://api.github.com/gists", json=data, headers=headers)
    if r.status_code == 201:
        return r.json()["html_url"]
    return None


def notify_discord_embeds(embeds):
    payload = {"embeds": embeds}
    requests.post(WEBHOOK_URL, json=payload)


while True:
    print(f"[{datetime.datetime.now()}] bb-domains is running...")
    remote_data = fetch_remote()
    local_data = fetch_local()
    if remote_data != local_data:
        added = [d for d in remote_data if d not in local_data]
        removed = [d for d in local_data if d not in remote_data]

        embeds = []

        if added:
            gist_url = create_gist(
                "\n".join(added), "bb-domains-added.txt", "Added domains"
            )
            if gist_url:
                embeds.append(
                    {
                        "title": f"Added Domains ({len(added)})",
                        "description": f"[View Gist]({gist_url})",
                        "color": 3066993,
                    }
                )

        if removed:
            gist_url = create_gist(
                "\n".join(removed), "bb-domains-removed.txt", "Removed domains"
            )
            if gist_url:
                embeds.append(
                    {
                        "title": f"Removed Domains ({len(removed)})",
                        "description": f"[View Gist]({gist_url})",
                        "color": 15158332,
                    }
                )

        if embeds:
            notify_discord_embeds(embeds)

        save_local(remote_data)

    time.sleep(4 * 60 * 60)
