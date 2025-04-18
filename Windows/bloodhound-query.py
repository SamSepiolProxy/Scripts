#!/usr/bin/env python3
"""
neo4j_query.py

Connects to a Neo4j HTTP endpoint, runs a user-specified Cypher query
and prints each returned node's 'name' property using 'row' format exclusively.
Credentials are set directly in the script configuration.
"""
import argparse
import sys
from typing import Dict, Any, List

import requests
from requests.auth import HTTPBasicAuth

# ==== Configuration: set your credentials here ====
USERNAME = 'neo4j'
PASSWORD = 'secret'
NEO4J_URL = 'http://localhost:7474'
API_ENDPOINT = '/db/data/transaction/commit'
# ================================================


def parse_arguments() -> argparse.Namespace:
    """
    Parse and return command-line arguments.
    --query allows specifying any Cypher query; defaults to searching Computers with 'mgt'.
    """
    parser = argparse.ArgumentParser(
        description='Run a Cypher query against Neo4j and print each node name.'
    )
    parser.add_argument(
        '-U', '--url',
        default=NEO4J_URL,
        help='Base URL of the Neo4j HTTP API'
    )
    parser.add_argument(
        '-q', '--query',
        default="MATCH (c:Computer) WHERE c.name =~ '.*((?i)mgt).*' RETURN c",
        help='Cypher query string to execute'
    )
    return parser.parse_args()


def run_query(url: str, username: str, password: str, query: str) -> Dict[str, Any]:
    """
    Execute the Cypher query using 'row' format and return parsed JSON.
    Exits on HTTP errors.
    """
    endpoint = url.rstrip('/') + API_ENDPOINT
    payload = {
        'statements': [
            {'statement': query, 'resultDataContents': ['row']}
        ]
    }
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    auth = HTTPBasicAuth(username, password)

    response = requests.post(endpoint, auth=auth, headers=headers, json=payload)
    if response.status_code == 401:
        sys.exit('Authentication error: check your username/password')
    if response.status_code >= 300:
        sys.exit(f'Failed to retrieve data (HTTP {response.status_code})')

    return response.json()


def extract_names(data: Dict[str, Any]) -> List[str]:
    """
    From the Neo4j response JSON in 'row' format, extract and return a list of node names.
    """
    entries = data.get('results', [])[0].get('data', [])
    names: List[str] = []
    for entry in entries:
        props = entry.get('row', [None])[0]
        if isinstance(props, dict) and 'name' in props:
            names.append(props['name'])
    return names


def main() -> None:
    args = parse_arguments()
    result = run_query(
        url=args.url,
        username=USERNAME,
        password=PASSWORD,
        query=args.query
    )

    names = extract_names(result)
    for name in names:
        print(name)


if __name__ == '__main__':
    main()