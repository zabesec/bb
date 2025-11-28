#!/usr/bin/env python3


def init_database(conn):
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            target VARCHAR(255) NOT NULL,
            scan_date TIMESTAMP DEFAULT NOW(),
            total_found INTEGER DEFAULT 0,
            new_found INTEGER DEFAULT 0,
            tools_used TEXT[]
        );
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS domains (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            target VARCHAR(255) NOT NULL,
            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW(),
            is_active BOOLEAN DEFAULT TRUE,
            UNIQUE(name, target)
        );
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_sources (
            scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
            source VARCHAR(50) NOT NULL,
            discovered_at TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (scan_id, domain_id, source)
        );
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS resolutions (
            id SERIAL PRIMARY KEY,
            domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
            resolved_ip VARCHAR(45),
            status_code INTEGER,
            response_time INTEGER,
            checked_at TIMESTAMP DEFAULT NOW()
        );
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS open_ports (
            id SERIAL PRIMARY KEY,
            domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
            port INTEGER NOT NULL,
            service VARCHAR(100),
            discovered_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(domain_id, port)
        );
    """
    )

    conn.commit()
    cursor.close()
