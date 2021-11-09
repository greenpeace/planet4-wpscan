#!/usr/bin/env python3
import json
import os
import requests

COMPOSER_FILE = 'https://raw.githubusercontent.com/greenpeace/planet4-base/main/composer.json'
WPSCAN_API = 'https://wpscan.com/api/v3/plugins/'
WPSCAN_TOKEN = os.getenv('WPSCAN_TOKEN')
WPSCAN_URL = 'https://wpscan.com/vulnerability/'
HEADERS = {
    'Authorization': 'Token token={0}'.format(WPSCAN_TOKEN)
}


def plugin_check(slug, version):
    r = requests.get('{0}{1}'.format(WPSCAN_API, slug), headers=HEADERS)
    try:
        vulnerabilities = r.json()[slug]['vulnerabilities']
    except KeyError:
        return False
    for v in vulnerabilities:
        if (v['fixed_in'] > version):
            print('Vulnerability affecting {0}: {1} - {2}{3}'.format(
                slug,
                v['title'],
                WPSCAN_URL,
                v['id'])
            )


if __name__ == '__main__':
    r = requests.get(COMPOSER_FILE)
    composer = json.loads(r.content)
    requirements = composer['require']

    for package in requirements:
        if 'wpackagist' in package:
            slug = package.split('/')[1]
            version = requirements[package]
            if '*' in version:
                version=version.replace('*', '999')
            plugin_check(slug, version)
