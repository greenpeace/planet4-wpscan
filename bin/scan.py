#!/usr/bin/env python3
import argparse
import json
import os
import requests
import subprocess

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
                try:
                    if (v['fixed_in'] <= version):
                        continue
                except TypeError:
                    pass
                output += 'Vulnerability affecting Wordpress: {0} - {1}{2}'.format(
                    v['title'],
                    WPSCAN_URL,
                    v['id'])

    return output


def check_wpscan(filename='composer.json'):
    with open(filename, 'r') as f:
        composer = json.loads(f.read())

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

    return output


def check_composer(filename='composer.json'):
    with open('composer-local.json', 'w') as f:
        content = '{}'
        f.write(content)

    bashCommand = 'composer install'
    subprocess.run(bashCommand.split())

    with open('updates.json', 'w') as f:
        bashCommand = 'composer outdated -D -f json'
        subprocess.run(bashCommand.split(), stdout=f)

    with open('updates.json', 'r') as f:
        packages = json.loads(f.read())['installed']

    output = ''
    for package in packages:
        output += '[{0}] {1}: {2} > {3}\n'.format(
            package['latest-status'], package['name'],
            package['version'], package['latest'])

    if not output:
        output = 'All packages are at latest version'

    return output


if __name__ == '__main__':
    # Options
    parser = argparse.ArgumentParser()
    parser.add_argument('--function',
                        choices=['wpscan', 'composer'],
                        help='Pick functionality',
                        required=True)
    args = parser.parse_args()

    # Parsed options
    function = args.function

    r = requests.get(COMPOSER_FILE)
    with open('composer.json', 'w') as f:
        f.write(r.text)

    if function == 'wpscan':
        output = check_wpscan()

    if function == 'composer':
        output = check_composer()

    print(output)
