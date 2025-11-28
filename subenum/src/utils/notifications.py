#!/usr/bin/env python3

import json
from datetime import datetime

import requests

from utils.colors import Colors


def send_discord_notification(webhook_url, target, scan_id, truly_new, reappeared=None, total_found=0):
    if not webhook_url or not truly_new:
        return False

    try:
        if truly_new:
            color = 0x00ff00
            title = f"🎯 New Domains Found - {target}"
        else:
            return False

        domain_list = []
        max_show = 10

        for i, domain in enumerate(sorted(truly_new)[:max_show], 1):
            domain_list.append(f"`{i}.` **{domain}**")

        remaining = len(truly_new) - max_show
        if remaining > 0:
            domain_list.append(f"_...and {remaining} more_")

        domains_text = "\n".join(domain_list) if domain_list else "None"

        fields = [
            {
                "name": "📊 Scan Statistics",
                "value": (
                    f"**New Domains:** {len(truly_new)}\n"
                    f"**Total Found:** {total_found}\n"
                    f"**Scan ID:** {scan_id}"
                ),
                "inline": True
            }
        ]

        if reappeared:
            fields.append({
                "name": "🔄 Reappeared",
                "value": f"{len(reappeared)} domains",
                "inline": True
            })

        fields.append({
            "name": "⏰ Scan Time",
            "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "inline": False
        })

        embed = {
            "title": title,
            "description": f"**Target:** `{target}`\n\n**New Domains:**\n{domains_text}",
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Subenum Notification"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

        payload = {
            "embeds": [embed]
        }

        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code == 204:
            print(f"[{Colors.GREEN}SUC{Colors.RESET}] Discord notification sent successfully")
            return True
        else:
            print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Discord notification failed: {response.status_code}")
            return False

    except Exception as e:
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Failed to send Discord notification: {str(e)}")
        return False


def should_notify(config, truly_new, reappeared):
    if not config or not config.get('discord', {}).get('enabled'):
        return False

    notify_new = config['discord'].get('notify_on_new', True)
    notify_reappeared = config['discord'].get('notify_on_reappeared', False)

    if notify_new and truly_new:
        return True

    if notify_reappeared and reappeared:
        return True

    return False
