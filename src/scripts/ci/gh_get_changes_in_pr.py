#!/usr/bin/env python3

import argparse
import gzip
import http.client
import json
import re
import sys

def main(args = None):
    if args is None:
        args = sys.argv

    re_git_sha = re.compile('[0-9A-Fa-f]{20}')

    parser = argparse.ArgumentParser()

    parser.add_argument('--base-commit', default='master', metavar='BRANCH')
    parser.add_argument('--api-host', default='api.github.com', metavar='HOST')
    parser.add_argument('--api-token', default=None)
    parser.add_argument('this_commit')

    args = vars(parser.parse_args())

    gh_api = args['api_host']
    this_commit = args['this_commit']
    base_commit = args['base_commit']

    if re_git_sha.match(this_commit) is None:
        print("The argument '%s' does not look like a git commit id" % (this_commit))
        return 1

    headers = {
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "gzip",
        "X-GitHub-Api-Version": "2022-11-28",
        "Host": gh_api,
        "User-Agent": "Botan gh_get_changes_in_pr.py",
    }

    if args.get('api_token'):
        headers['Authorization'] = 'Bearer %s' % (args['api_token'])

    api_req = "/repos/randombit/botan/compare/%s...%s?per_page=0" % (base_commit, this_commit)

    gh = http.client.HTTPSConnection(gh_api)
    gh.request('GET', api_req, headers=headers)
    resp = gh.getresponse()

    if resp.status != 200:
        print("GH API call returned unexpected status %d" % (resp.status))
        return 1

    is_gzip = False
    content_encoding = resp.getheader('Content-Encoding')
    if content_encoding:
        if content_encoding == 'gzip':
            is_gzip = True
        else:
            print("Unexpected Content-Encoding %s" % (content_encoding))
            return 1

    body = resp.read()

    if is_gzip:
        body = gzip.decompress(body)

    j = json.loads(body)

    if 'files' not in j:
        return 0

    for f in j['files']:
        print(f['filename'])

    return 0

if __name__ == '__main__':
    sys.exit(main())

