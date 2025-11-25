#!/usr/bin/env python3

from utils.colors import Colors


def export_to_files(conn, scan_id, output_dir):
    cursor = conn.cursor()

    print(f"\n[{Colors.CYAN}INF{Colors.RESET}] Exporting to files...")

    cursor.execute(
        """
        SELECT DISTINCT d.name
        FROM domains d
        JOIN scan_sources ss ON d.id = ss.domain_id
        WHERE ss.scan_id = %s
        ORDER BY d.name
    """,
        (scan_id,),
    )

    with open(f"{output_dir}/domains-tracked.txt", "w") as f:
        for row in cursor.fetchall():
            f.write(f"{row[0]}\n")

    for source in [
        "subfinder",
        "findomain",
        "assetfinder",
        "crtsh",
        "chaos",
        "shuffledns",
    ]:
        cursor.execute(
            """
            SELECT DISTINCT d.name
            FROM domains d
            JOIN scan_sources ss ON d.id = ss.domain_id
            WHERE ss.scan_id = %s AND ss.source = %s
            ORDER BY d.name
        """,
            (scan_id, source),
        )

        results = cursor.fetchall()
        if results:
            with open(f"{output_dir}/{source}.txt", "w") as f:
                for row in results:
                    f.write(f"{row[0]}\n")

    cursor.close()
    print(f"[{Colors.GREEN}SUC{Colors.RESET}] Files exported to {output_dir}")
