#!/usr/bin/env python3
import json
import os
import requests

COMPOSER_FILE = 'https://raw.githubusercontent.com/greenpeace/planet4-base/main/composer.json'
WPSCAN_PLAUGINS_API = 'https://wpscan.com/api/v3/plugins/'
WPSCAN_WP_API = 'https://wpscan.com/api/v3/wordpresses/'
WPSCAN_TOKEN = os.getenv('WPSCAN_TOKEN')
WPSCAN_URL = 'https://wpscan.com/vulnerability/'
HEADERS = {
    'Authorization': 'Token token={0}'.format(WPSCAN_TOKEN)
}


def plugin_check(slug, version):
    r = requests.get('{0}{1}'.format(WPSCAN_PLAUGINS_API, slug), headers=HEADERS)
    plugins = r.json()
    output = ''

    try:
        vulnerabilities = plugins[slug]['vulnerabilities']
    except KeyError:
        return output

    for v in vulnerabilities:
        if (v['fixed_in'] > version):
            output += 'Vulnerability affecting {0}: {1} - {2}{3}'.format(
                slug,
                v['title'],
                WPSCAN_URL,
                v['id'])

    return output


def wp_check(version):
    r = requests.get('{0}{1}'.format(WPSCAN_WP_API, version.replace('.', '')), headers=HEADERS)
    wps = r.json()
    output = ''

    if len(wps) == 0:
        return output

    wp_major = version.replace('.', '')[:2]
    for key, value in wps.items():
        item = key.replace('.', '')[:2]
        if item == wp_major:
            vulnerabilities = value['vulnerabilities']
            for v in vulnerabilities:
                if (v['fixed_in'] > version):
                    output += 'Vulnerability affecting {0}: {1} - {2}{3}'.format(
                        slug,
                        v['title'],
                        WPSCAN_URL,
                        v['id'])

    return output


if __name__ == '__main__':
    r = requests.get(COMPOSER_FILE)
    composer = json.loads(r.content)

    requirements = composer['require']
    wp_version = composer['extra']['wp-version']
    output = ''

    # Check current WP version
    output = wp_check(wp_version)

    # Check all installed WP plugins
    for package in requirements:
        if 'wpackagist' in package:
            slug = package.split('/')[1]
            version = requirements[package]
            if '*' in version:
                version = version.replace('*', '999')
            vulns = plugin_check(slug, version)
            if vulns:
                output += vulns

    if not output:
        output = 'No active vulnerability found'

    print(output)
