#!/usr/bin/env python3


def create_scan(conn, target):
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO scans (target) VALUES (%s) RETURNING id""",
        (target,),
    )
    scan_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    return scan_id


def is_first_scan(conn, target):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COUNT(*) FROM scans WHERE target = %s
    """,
        (target,),
    )
    count = cursor.fetchone()[0]
    cursor.close()
    return count == 0


def store_domains_batch(conn, scan_id, domains_list, target, source):
    if not domains_list:
        return 0

    cursor = conn.cursor()

    for domain in domains_list:
        cursor.execute(
            """
            INSERT INTO domains (name, target, last_seen)
            VALUES (%s, %s, NOW())
            ON CONFLICT (name, target)
            DO UPDATE SET last_seen = NOW(), is_active = TRUE
            RETURNING id
        """,
            (domain.strip(), target),
        )

        domain_id = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO scan_sources (scan_id, domain_id, source)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
        """,
            (scan_id, domain_id, source),
        )

    conn.commit()
    cursor.close()
    return len(domains_list)


def get_previous_scan_domains(conn, target):
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id FROM scans
        WHERE target = %s
        ORDER BY scan_date DESC
        LIMIT 1 OFFSET 1
    """,
        (target,),
    )

    result = cursor.fetchone()
    if not result:
        cursor.close()
        return None

    prev_scan_id = result[0]

    cursor.execute(
        """
        SELECT DISTINCT d.name
        FROM domains d
        JOIN scan_sources ss ON d.id = ss.domain_id
        WHERE ss.scan_id = %s
    """,
        (prev_scan_id,),
    )

    prev_domains = set(row[0] for row in cursor.fetchall())
    cursor.close()

    return prev_domains


def get_current_scan_domains(conn, scan_id):
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT DISTINCT d.name
        FROM domains d
        JOIN scan_sources ss ON d.id = ss.domain_id
        WHERE ss.scan_id = %s
    """,
        (scan_id,),
    )

    current_domains = set(row[0] for row in cursor.fetchall())
    cursor.close()

    return current_domains


def update_scan_stats(conn, scan_id, total, new_count):
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE scans
        SET total_found = %s, new_found = %s
        WHERE id = %s
    """,
        (total, new_count, scan_id),
    )
    conn.commit()
    cursor.close()


def store_open_ports(conn, scan_id, port_results, target, batch_size=50):
    if not port_results:
        return 0

    cursor = conn.cursor()
    stored = 0
    batch_count = 0

    for result in port_results:
        if ":" in result:
            parts = result.split(":")
            if len(parts) >= 2:
                domain_part = parts[-2].replace("http://", "").replace("https://", "")
                port = parts[-1].strip()

                cursor.execute(
                    "SELECT id FROM domains WHERE name = %s AND target = %s",
                    (domain_part, target),
                )

                domain_result = cursor.fetchone()
                if domain_result:
                    domain_id = domain_result[0]

                    cursor.execute(
                        """
                        INSERT INTO open_ports (domain_id, port, discovered_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (domain_id, port) DO NOTHING
                        """,
                        (domain_id, int(port)),
                    )
                    stored += 1
                    batch_count += 1

                    if batch_count >= batch_size:
                        conn.commit()
                        batch_count = 0

    if batch_count > 0:
        conn.commit()
    cursor.close()
    return stored



def store_resolutions(conn, resolved_urls, target):
    if not resolved_urls:
        return 0

    cursor = conn.cursor()
    stored = 0

    for url in resolved_urls:
        domain = (
            url.replace("http://", "")
            .replace("https://", "")
            .split("/")[0]
            .split(":")[0]
        )

        cursor.execute(
            """
            SELECT id FROM domains WHERE name = %s AND target = %s
        """,
            (domain, target),
        )

        result = cursor.fetchone()
        if result:
            domain_id = result[0]

            cursor.execute(
                """
                INSERT INTO resolutions (domain_id, checked_at)
                VALUES (%s, NOW())
            """,
                (domain_id,),
            )
            stored += 1

    conn.commit()
    cursor.close()
    return stored


def purge_target_data(conn, target):
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM scans WHERE target = %s", (target,))
    scan_ids = [row[0] for row in cursor.fetchall()]

    if scan_ids:
        cursor.execute("DELETE FROM scans WHERE target = %s", (target,))
        cursor.execute("DELETE FROM domains WHERE target = %s", (target,))
        conn.commit()

    cursor.close()
    return len(scan_ids)


def purge_all_data(conn):
    cursor = conn.cursor()

    cursor.execute(
        "TRUNCATE TABLE scan_sources, resolutions, open_ports, domains, scans RESTART IDENTITY CASCADE"
    )

    conn.commit()
    cursor.close()
