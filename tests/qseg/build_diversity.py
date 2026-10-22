"""核对三份相同输入候选的资源身份、VM材料、分派顺序与设备语义差异。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect(directory):
    native = directory / 'native'
    receipt = json.loads((native / 'protection.json').read_text())
    rows = json.loads((native / 'segments.json').read_text())['segments']
    resources = {row['name']: (row['id'], row['resourceSha256']) for row in rows if row['kind'] == 1}
    ir = (native / 'protected.raw.ll').read_text()
    clones = re.findall(r'^define [^\n]*@vm_interpreter_(d2c_[0-9a-f]+)_k([0-9a-f]+)\([^\n]*\{\n(.*?)^}', ir, re.M | re.S)
    keys, dispatch = {}, {}
    for name, key, body in clones:
        keys[name] = digest(key.encode())
        start = body.find('load volatile i64, ptr @vmp_interpreter_clone_salt_')
        assert start >= 0, f'missing dispatch: {name}'
        order = re.findall(r'xor i8 (\d+), %\d+', body[start:])
        assert order, f'missing opcode chain: {name}'
        dispatch[name] = digest(','.join(order).encode())
    assert set(keys) == set(receipt['symbols']) == set(resources), 'VM manifest differs'
    result = json.loads((directory / 'device-results.json').read_text())
    semantics = {row['main']: row['output'] for row in result['results'] if row['mode'] == 'protected'}
    assert len(semantics) == 2, 'requires Java and Kotlin device results'
    with zipfile.ZipFile(directory / 'original.jar') as archive:
        business = digest(archive.read('sample/Logic.class'))
    return {'path': str(directory.resolve()), 'businessClassSha256': business,
            'certificateSha256': receipt['certificateSha256'], 'containerSha256': receipt['containerSha256'],
            'librarySha256': receipt['librarySha256'], 'semantics': semantics,
            'resources': resources, 'resourceIds': {name: value[0] for name, value in resources.items()},
            'resourceCiphertextDigests': {name: value[1] for name, value in resources.items()},
            'functionKeyDigests': keys, 'dispatchOrderDigests': dispatch}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert len(args.fixtures) == 3, 'requires exactly three independent builds'
    builds = [inspect(path) for path in args.fixtures]
    for key in ('businessClassSha256', 'certificateSha256', 'semantics'):
        assert all(row[key] == builds[0][key] for row in builds), f'input/semantics differ: {key}'
    counts = {}
    for field in ('resourceIds', 'resourceCiphertextDigests', 'functionKeyDigests', 'dispatchOrderDigests'):
        assert all(set(row[field]) == set(builds[0][field]) for row in builds), f'coverage differs: {field}'
        counts[field] = sum(len({str(row[field][name]) for row in builds}) == 3 for name in builds[0][field])
        assert counts[field] > 0, f'no three-way diversity: {field}'
    for key in ('containerSha256', 'librarySha256'):
        assert len({row[key] for row in builds}) == 3, f'no diversity: {key}'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'builds': builds, 'threeWayChangedMethods': counts,
                                      'vmMethods': len(builds[0]['resources']), 'passed': True}, indent=2) + '\n')
    print(json.dumps(counts))


if __name__ == '__main__':
    main()
