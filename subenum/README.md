# Subenum

A subdomain enumeration tool for bug bounty hunting that aggregates results from multiple sources and tracks discoveries over time using PostgreSQL.

## Features

-   **Multiple enumeration sources**: Subfinder, Findomain, Assetfinder, crt.sh, Chaos, ShuffleDNS
-   **DNS resolution**: Validates discovered subdomains with httpx
-   **Port scanning**: Optional port discovery with naabu
-   **Database tracking**: PostgreSQL-backed history of all scans
-   **Diff reports**: Shows new, reappeared, and disappeared domains between scans
-   **Automated scheduling**: Run scans on a schedule
-   **Discord notifications**: Get notified about new discoveries
-   **Docker-based**: All tools run in isolated containers

## Requirements

-   Docker & Docker Compose
-   Python 3.12+
-   Bash (for wrapper script)

## Setup

**Docker File Sharing**

Before running the tool, ensure Docker has access to your subenum directory.

Open Docker Desktop → Settings → Resources → File Sharing
Add the path to your subenum directory.

Docker Desktop (Linux):

File sharing is typically automatic, but if you encounter permission issues:

```bash
sudo chown -R $USER:$USER /path/to/subenum
```

## Quick Start

1. **Run setup**

    ```bash
    ./setup.sh
    ```

    - Builds Docker images with all enumeration tools
    - Starts the PostgreSQL database container
    - Installs Python dependencies
    - Makes the subenum wrapper executable
    - Creates necessary directories (config, wordlists)
    - Starts the scheduler service

2. **Configure**

    ```bash
    cp example.config.yml config.yml
    # Edit config.yml with your settings
    ```

3. **Add an alias to subenum wrapper**

    ```bash
    echo 'alias subenum="bash /path/to/subenum/subenum"' >> ~/.zshrc
    source ~/.zshrc
    ```

4. **Run a scan**
    ```bash
    subenum -d example.com -sd -ps 1000 -o output/ -export
    ```

## Usage

```
usage: subenum.py [-h] -d example.com [-sd] [-r resolvers.txt] [-w wordlist.txt] [-ps WIDTH] [-o output/] [-export] [-purge]

Subdomain enumeration with database tracking

options:
  -h, --help        show this help message and exit
  -d example.com    Target domain
  -sd               Run DNS bruteforcing with shuffledns
  -r resolvers.txt  Resolvers file for shuffledns
  -w wordlist.txt   Wordlist file for shuffledns
  -ps WIDTH         Port scan: 100, 1000, full
  -o output/        Output directory
  -export           Export results to files
  -purge            Purge target's previous data
```

### Basic scan

```bash
subenum -d example.com
```

### Scan with DNS bruteforcing

```bash
subenum -d example.com -sd
```

### Scan with custom resolvers and wordlist

```bash
subenum -d example.com -sd -r wordlists/resolvers.txt -w wordlists/subdomains.txt
```

### Scan with port scanning

```bash
subenum -d example.com -ps 100    # Top 100 ports
subenum -d example.com -ps 1000   # Top 1000 ports
subenum -d example.com -ps full   # All ports
```

### Export results to files

```bash
subenum -d example.com -o output/ -export
```

### Purge previous scan data

```bash
subenum -d example.com -purge
```

## Configuration

Edit `config.yml` to customize:

### Database

```yaml
database_url: postgresql://subenum:subenum@subenum-db:5432/subenum
```

### Tool Paths

```yaml
paths:
    resolvers: /wordlists/resolvers.txt
    subdomains_wordlist: /wordlists/internal-subdomains.txt
```

### API Keys

```yaml
chaos_api_key: your-api-key-here
```

### Timeouts

```yaml
timeouts:
    default: 900
    shuffledns: 3600
    portscan: 3600
```

### Automated Scheduling

```yaml
scheduler:
    enabled: true
    times:
        - 00:00
        - 12:00
    targets:
        - example.com
        - another.com
```

### Discord Notifications

```yaml
notifications:
    discord:
        enabled: true
        webhook_url: https://discord.com/
        notify_on_new: true
        notify_on_reappeared: false
        max_domains_shown: 10
```

## Tools Included

-   **[Subfinder](https://github.com/projectdiscovery/subfinder)** - Subdomain discovery using passive sources
-   **[Findomain](https://github.com/Findomain/Findomain)** - Fast subdomain enumeration
-   **[Assetfinder](https://github.com/tomnomnom/assetfinder)** - Find domains and subdomains
-   **[crt.sh](https://crt.sh)** - Certificate transparency logs
-   **[Chaos](https://github.com/projectdiscovery/chaos-client)** - ProjectDiscovery's subdomain dataset (requires API key)
-   **[ShuffleDNS](https://github.com/projectdiscovery/shuffledns)** - DNS bruteforce tool
-   **[httpx](https://github.com/projectdiscovery/httpx)** - HTTP probe and validation
-   **[naabu](https://github.com/projectdiscovery/naabu)** - Port scanner
-   **[dnsx](https://github.com/projectdiscovery/dnsx)** - DNS toolkit
-   **[MassDNS](https://github.com/blechschmidt/massdns)** - High-performance DNS resolver

## Database Schema

Subenum tracks:

-   **Scans**: Each enumeration run with timestamps
-   **Domains**: All discovered subdomains with first/last seen dates
-   **Sources**: Which tool found each domain
-   **Resolutions**: HTTP resolution results
-   **Open Ports**: Discovered open ports per domain

## Output Files

When using `-o output/ -export`:

```
output/
├── domains-tracked.txt    # All domains from this scan
├── domains-raw.txt        # Unresolved domains
├── domains-resolved.txt   # HTTP-validated domains
├── open-ports.txt         # Discovered open ports
├── subfinder.txt          # Subfinder results
├── findomain.txt          # Findomain results
├── assetfinder.txt        # Assetfinder results
├── crtsh.txt              # crt.sh results
├── chaos.txt              # Chaos results
└── shuffledns.txt         # ShuffleDNS results
```

## Scheduler

The scheduler automatically runs scans at configured times:

```bash
# Start the scheduler
docker compose up -d subenum-scheduler

# View scheduler logs
docker compose logs -f subenum-scheduler
```

The scheduler will:

-   Load targets from config or database
-   Run scans at specified times
-   Send Discord notifications (if configured)
-   Track all results in the database

## Tips

-   First scan of a target will show all domains as "new"
-   Subsequent scans show diffs: new, reappeared, disappeared
-   Use `-sd` for deeper enumeration (takes longer)
-   Port scanning can be slow - use specific widths (100/1000)
-   Configure Discord webhooks to stay updated on new findings
-   The scheduler is great for monitoring targets continuously

## Common Issues

**Database connection failed**

```bash
docker compose up -d subenum-db
# Wait a few seconds for database to be ready
```

**Tool not found**

```bash
docker compose build subenum
```

**Permission denied on subenum wrapper**

```bash
chmod +x subenum
```

## License

This tool is for authorized security testing only. Always obtain proper authorization before scanning targets.
