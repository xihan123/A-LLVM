"""Verify final, already signed APK outputs without modifying them (stdlib only)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile
from dex2c_artifacts import verify_wrappers
from seal_qseg import zip_entry_range


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check_lifetimes(receipt, segments):
    """旧回执只支持固定驻留；新 ABI 的回收声明必须与所有分段一致。"""
    abi = receipt.get('qsegLifetimeAbi', 0)
    require(type(abi) is int and abi in (0, 1), 'unsupported QSEG lifetime ABI')
    if abi == 0:
        require(not receipt.get('vmLifetimePolicies') and not receipt.get('idlePlaintextBudgetBytes') and
                all(row.get('lifetime', 'pinned-legacy') == 'pinned-legacy'
                    for row in segments['segments'] if row['kind'] == 1), 'legacy receipt claims reclamation')
        return
    policies = receipt.get('vmLifetimePolicies')
    require(receipt.get('idlePlaintextBudgetBytes') == 1048576 and isinstance(policies, dict) and
            set(policies) == set(receipt['symbols']), 'QSEG lifetime policy coverage differs')
    modes = ('lease-v1', 'pinned-unproven-unwind', 'pinned-legacy')
    observed = {}
    for row in segments['segments']:
        mode = row.get('lifetime')
        require((row['kind'] == 2 and mode == 'copy-v1') or
                (row['kind'] == 1 and mode in modes), 'unsupported segment lifetime policy')
        if row['kind'] == 1:
            name = row['name']
            require(name not in observed or observed[name] == mode, 'inconsistent chunk lifetime policy')
            observed[name] = mode
    require(all(observed.get(name) == mode for name, mode in policies.items()),
            'segment lifetime policy differs from protection receipt')


class Cursor:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, n):
        require(0 <= n <= len(self.data) - self.offset, 'truncated signing record')
        result = self.data[self.offset:self.offset + n]; self.offset += n
        return result

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def lp(self):
        return Cursor(self.take(self.u32()))

    def end(self):
        return self.offset == len(self.data)


def check_runtime_format(data, min_sdk):
    """Reject formats excluded by the native verifier even if apksigner accepts them."""
    eocd = next((i for i in range(len(data) - 22, max(-1, len(data) - 65558), -1)
                 if data[i:i + 4] == b'PK\x05\x06' and i + 22 + int.from_bytes(data[i + 20:i + 22], 'little') == len(data)), None)
    require(eocd is not None, 'missing EOCD')
    cd = struct.unpack_from('<I', data, eocd + 16)[0]
    require(24 <= cd <= eocd and data[cd - 16:cd] == b'APK Sig Block 42', 'APK v2/v3 signature required')
    size = struct.unpack_from('<Q', data, cd - 24)[0]
    require(24 <= size <= min(16 << 20, cd - 8), 'invalid signing block length')
    start = cd - size - 8
    require(struct.unpack_from('<Q', data, start)[0] == size, 'signing block lengths disagree')
    pairs = Cursor(data[start + 8:cd - 24]); blocks = {}
    while not pairs.end():
        n = struct.unpack('<Q', pairs.take(8))[0]; record = Cursor(pairs.take(n)); kind = record.u32()
        require(kind != 0x1B93AD61, 'APK v3.1 is unsupported')
        if kind in (0x7109871A, 0xF05368C0):
            require(kind not in blocks, 'duplicate signature scheme')
            blocks[kind] = record.lp()
            require(record.end(), 'invalid scheme record')
    require(blocks, 'APK v2/v3 signature required')
    require(min_sdk >= 28 or 0x7109871A in blocks, 'API 26/27 require APK v2')
    for kind, signers in blocks.items():
        signer = signers.lp(); require(signers.end(), 'multiple signers are unsupported')
        signed = signer.lp()
        if kind == 0xF05368C0:
            low, high = signer.u32(), signer.u32()
            require(low <= max(28, min_sdk) and high == 0x7FFFFFFF, 'v3 SDK range cannot cover the supported release')
        signatures = signer.lp(); public = signer.lp(); require(signer.end() and public.data, 'invalid signer')
        digests = signed.lp(); certificates = signed.lp()
        require(certificates.data, 'missing certificate')
        if kind == 0xF05368C0:
            require((signed.u32(), signed.u32()) == (low, high), 'v3 SDK ranges disagree')
        attrs = signed.lp()
        algorithms = []
        for records in (signatures, digests):
            ids = []
            while not records.end():
                record = records.lp(); algorithm = record.u32(); value = record.lp()
                require(record.end() and value.data and algorithm in (0x101, 0x102, 0x103, 0x104, 0x201, 0x202), 'unsupported signature algorithm')
                require(algorithm not in ids and len(ids) < 16, 'duplicate or excessive algorithms'); ids.append(algorithm)
            require(ids, 'missing signatures or digests'); algorithms.append(ids)
        require(algorithms[0] == algorithms[1], 'signature/digest algorithm lists differ')
        seen = set()
        while not attrs.end():
            attr = attrs.lp(); attr_id = attr.u32()
            require(attr_id not in seen and len(seen) < 128, 'duplicate or excessive attributes'); seen.add(attr_id)
            require(attr_id not in (0x3BA06F8C, 0x559F8B02, 0xC2A6B3BA), 'signature rotation is unsupported')
            if attr_id == 0xBEEFF00D:
                require(kind == 0x7109871A and attr.u32() == 3 and attr.end() and 0xF05368C0 in blocks, 'signature scheme stripped')


def verify(apks, native, generated, java, apksigner, min_sdk, report):
    report.unlink(missing_ok=True)
    receipt_file, selection_file = native / 'protection.json', generated / 'selection.json'
    receipt = json.loads(receipt_file.read_text())
    if not receipt['protectedMethods'] and not receipt.get('protectedStrings', 0):
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({'schemaVersion': 1, 'protectedMethods': 0}) + '\n'); return
    selection_bytes = selection_file.read_bytes(); selection = json.loads(selection_bytes)
    require(digest(selection_bytes) == receipt['selectionSha256'], 'selection receipt changed')
    methods = selection['methods']
    require(len(methods) == receipt['protectedMethods'], 'method count differs')
    require(len({m['method'] for m in methods}) == len(methods) and
            len({m['symbol'] for m in methods}) == len(methods), 'duplicate selected method or symbol')
    require(all(m['protection'] in ('vmp', 'native-cse') for m in methods), 'unknown protection policy')
    require({m['symbol'] for m in methods if m['protection'] == 'vmp'} == set(receipt['symbols']), 'VMP manifest differs')
    require({m['symbol'] for m in methods if m['protection'] == 'native-cse'} == set(receipt['nativeSymbols']), 'native manifest differs')
    strings = selection.get('strings', {})
    string_count = strings.get('uniqueStrings', 0)
    require(string_count == receipt.get('protectedStrings', 0), 'string count differs')
    if string_count:
        require(digest((generated / 'string-selection.json').read_bytes()) == receipt['stringSelectionSha256'], 'string selection receipt changed')
        require(json.loads((generated / 'string-selection.json').read_text()) == strings, 'string manifests differ')
        require(receipt.get('stringSymbols') == [strings['symbol']], 'string dispatcher differs')
        require(strings['occurrences'] == len(strings['sites']) and
                {s['index'] for s in strings['sites']} == set(range(string_count)), 'string index coverage differs')
        require(receipt.get('cseHardened') and receipt.get('certificateBound') and receipt.get('selfCheckEntry') and
                receipt.get('vmpPost') and receipt.get('cseVmpMethods') == 2, 'string protection chain incomplete')
        require(digest((generated / 'classes.jar').read_bytes()) == receipt['classesSha256'], 'transformed classes changed')
    library_path = 'lib/arm64-v8a/lib' + selection['library'] + '.so'
    asset_path = 'assets/' + selection['library'] + '.qseg'
    libraries, containers, outputs = 0, 0, []
    for apk in apks:
        result = subprocess.run([str(java), '-jar', str(apksigner), 'verify', '--verbose', '--print-certs',
                                 '--min-sdk-version', str(min_sdk), str(apk)], capture_output=True, text=True, encoding='utf-8', errors='replace')
        require(result.returncode == 0, 'apksigner rejected ' + apk.name + ': ' + result.stdout + result.stderr)
        certificates = sorted(set(value.lower() for value in re.findall(
            r'^(?:Signer #\d+|V[0-9.]+ Signer(?: #\d+)?):? certificate SHA-256 digest: ([0-9a-fA-F]{64})$', result.stdout, re.M)))
        signer_counts = re.findall(r'^Number of signers: (\d+)\s*$', result.stdout, re.M)
        require(signer_counts == ['1'] and len(certificates) == 1 and certificates[0] == receipt['certificateSha256'], 'APK certificate differs from compiled identity')
        data = apk.read_bytes()
        if receipt.get('apkSignatureVerification'):
            check_runtime_format(data, min_sdk)
        with zipfile.ZipFile(apk) as z:
            names = z.namelist(); require(len(names) == len(set(names)), 'duplicate ZIP entry')
            for entry in z.infolist():
                if entry.filename.startswith('lib/') and entry.filename.endswith('.so'):
                    binary = z.read(entry)
                    require(entry.filename.startswith('lib/arm64-v8a/') and len(binary) >= 20 and
                            binary[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', binary, 18)[0] == 183,
                            'unsupported SO ABI: ' + entry.filename)
            if library_path in names:
                require(digest(z.read(library_path)) == receipt['librarySha256'], 'packaged SO differs')
                libraries += 1
            if asset_path in names:
                require(receipt['segmentedData'] and digest(z.read(asset_path)) == receipt['containerSha256'], 'packaged QSEG differs')
                require(z.getinfo(asset_path).compress_type == zipfile.ZIP_STORED, 'QSEG must be STORED')
                zip_entry_range(data, z.getinfo(asset_path), z.start_dir)
                require(library_path in names, 'QSEG must share its SO APK'); containers += 1
            require(all(not name.endswith('.qseg') or name == asset_path for name in names), 'unexpected QSEG container')
        outputs.append({'file': apk.name, 'sha256': digest(data), 'bytes': len(data), 'certificateSha256': certificates[0].lower()})
    require(libraries >= 1 and containers == (libraries if receipt['segmentedData'] else 0), 'missing SO or container')
    if receipt['segmentedData']:
        require(digest((native / 'segments.json').read_bytes()) == receipt['segmentsReceiptSha256'], 'segment receipt changed')
        segments = json.loads((native / 'segments.json').read_text())
        require(segments.get('schemaVersion') == 1 and segments.get('containerSha256') == receipt['containerSha256'] and
                segments.get('containerBytes') == receipt['containerBytes'], 'segment receipt identity differs')
        check_lifetimes(receipt, segments)
    verify_wrappers(apks, selection)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({'schemaVersion': 1, 'protectedMethods': len(methods), 'protectedStrings': string_count, 'apkSignatureVerification': receipt.get('apkSignatureVerification', False),
                                  'protectionSha256': digest(receipt_file.read_bytes()), 'apks': outputs}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, action='append', required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--apksigner', type=Path, required=True)
    parser.add_argument('--min-sdk', type=int, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--independent-apks', action='store_true', help='AGP APK outputs are alternative installable APKs, not a split install set')
    args = parser.parse_args()
    if args.independent_apks and len(args.apk) > 1:
        args.report.unlink(missing_ok=True)
        outputs = []
        with tempfile.TemporaryDirectory(prefix='dex2c-apk-') as directory:
            result = Path(directory) / 'verified.json'
            for apk in args.apk:
                verify([apk], args.native, args.generated, args.java, args.apksigner, args.min_sdk, result)
                outputs.append(json.loads(result.read_text()))
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'schemaVersion': 1, 'outputs': outputs}, indent=2) + '\n')
    else:
        verify(args.apk, args.native, args.generated, args.java, args.apksigner, args.min_sdk, args.report)
