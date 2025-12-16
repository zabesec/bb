import csv
import re
import argparse
import os

def is_domain(identifier):
    domain_pattern = r'^(?!.*\*)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, identifier))

def is_wildcard(identifier):
    return '*' in identifier

def clean_wildcard(identifier):
    if identifier.startswith('*.'):
        identifier = identifier[2:]
    elif identifier.startswith('*'):
        identifier = identifier[1:]
    
    if identifier.startswith('.'):
        identifier = identifier[1:]
    
    identifier = re.sub(r'^[a-zA-Z0-9\-]*\*\.?', '', identifier)
    
    return identifier

def extract_identifiers(csv_file, bounty_only, domain_only, wildcards, others, output_dir):
    domains = []
    wildcard_list = []
    other_list = []
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            identifier = row['identifier'].strip()
            eligible = row['eligible_for_bounty'].strip().lower() == 'true'
            
            if bounty_only and not eligible:
                continue
            
            if is_wildcard(identifier):
                if wildcards:
                    cleaned = clean_wildcard(identifier)
                    if cleaned:
                        wildcard_list.append(cleaned)
            elif is_domain(identifier):
                if domain_only or not (wildcards or others):
                    domains.append(identifier)
            else:
                if others:
                    other_list.append(identifier)
    
    os.makedirs(output_dir, exist_ok=True)
    
    if domains:
        with open(os.path.join(output_dir, 'domains.txt'), 'w') as f:
            f.write('\n'.join(sorted(set(domains))))
    
    if wildcard_list:
        with open(os.path.join(output_dir, 'wildcards.txt'), 'w') as f:
            f.write('\n'.join(sorted(set(wildcard_list))))
    
    if other_list:
        with open(os.path.join(output_dir, 'others.txt'), 'w') as f:
            f.write('\n'.join(sorted(set(other_list))))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_file', help='Path to CSV file')
    parser.add_argument('-bounty', action='store_true', help='Filter for bounty eligible only')
    parser.add_argument('-domain', action='store_true', help='Extract domains only')
    parser.add_argument('-wildcards', action='store_true', help='Extract and clean wildcards')
    parser.add_argument('-others', action='store_true', help='Extract non-domain identifiers')
    parser.add_argument('-output', default='output', help='Output directory')
    
    args = parser.parse_args()
    
    extract_identifiers(
        args.csv_file,
        args.bounty,
        args.domain,
        args.wildcards,
        args.others,
        args.output
    )

if __name__ == '__main__':
    main()
