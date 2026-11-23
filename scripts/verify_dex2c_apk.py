"""Verify final, already signed APK outputs without modifying them (stdlib only)."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
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


def check_method_receipt(receipt, selection):
    """A total count cannot prove that a declared VM method reached the VM compiler."""
    methods = selection['methods']
    vm = {m['symbol'] for m in methods if m['protection'] == 'vmp'}
    native = {m['symbol'] for m in methods if m['protection'] == 'native-cse'}
    for field, expected in (('vmpMethods', len(vm)), ('nativeMethods', len(native))):
        require(type(receipt.get(field)) is int and receipt[field] == expected, field + ' count differs')
    require(len(receipt['symbols']) == len(vm) and len(receipt['nativeSymbols']) == len(native),
            'duplicate receipt symbol')
    for field in ('cseHardened', 'certificateBound'):
        require(receipt.get(field) is True, 'missing protection receipt: ' + field)
    bytecodes = receipt.get('methodBytecodeBytes', {})
    require(isinstance(bytecodes, dict) and set(bytecodes) == vm and
            all(type(n) is int and n > 0 for n in bytecodes.values()), 'per-method VMP bytecode coverage differs')
    if vm:
        for field in ('vmpStrict', 'vmpPost', 'selfCheckEntry'):
            require(receipt.get(field) is True, 'missing VMP receipt: ' + field)
        branches = receipt.get('nativeIndirectBranches', {})
        require(isinstance(branches, dict) and vm <= branches.keys() and
                all(type(n) is int and n >= 0 for n in branches.values()), 'per-method VMP post coverage differs')
    require(type(receipt.get('segmentedData')) is bool, 'invalid segmented-data mode')
    segmented = receipt['segmentedData']
    require(receipt.get('bytecodeVerifiedInContainer') is segmented and
            receipt.get('bytecodeVerifiedInLibrary') is (not segmented), 'VMP bytecode location differs')


def check_requirements(selection, requirements):
    """Match a frozen, explicit denominator; never derive requirements from selection counts."""
    require(isinstance(requirements, dict) and requirements.get('schemaVersion') == 1 and
            isinstance(requirements.get('methods'), list) and requirements['methods'], 'invalid critical method requirements')
    selected = {row['method']: row for row in selection['methods']}
    if 'registrationIntegrityRecheck' in requirements:
        require(type(requirements['registrationIntegrityRecheck']) is bool and
                selection.get('registrationIntegrityRecheck', False) is requirements['registrationIntegrityRecheck'],
                'critical registration integrity recheck differs')
    observed, rows = set(), []
    for row in requirements['methods']:
        require(isinstance(row, dict) and isinstance(row.get('method'), str) and row['method'] and
                row.get('protection') in ('vmp', 'native-cse'), 'invalid critical method requirement')
        key = (row['method'], row.get('entry'))
        require(row.get('entry') is None or isinstance(row['entry'], str) and row['entry'],
                'invalid inherited critical entry')
        require(key not in observed, 'duplicate critical method requirement'); observed.add(key)
        actual = selected.get(row['method'])
        require(actual is not None and actual.get('protection') == row['protection'],
                'critical method protection differs: ' + row['method'])
        if 'integrityRecheck' in row:
            require(type(row['integrityRecheck']) is bool and
                    actual.get('integrityRecheck', False) is row['integrityRecheck'],
                    'critical method integrity recheck differs: ' + row['method'])
        if row.get('entry') is not None:
            require(selection.get('inherited', {}).get(row['entry']) == row['method'],
                    'critical inherited target differs: ' + row['entry'])
        rows.append({**row, 'symbol': actual['symbol'], 'bridge': actual['bridge'],
                     'validationStatus': 'passed', 'scope': 'signed-apk-static'})
    return rows


def direct_ir_call(line):
    direct = re.match(r'^\s*(?:%[^=\n]+?=\s*)?(?:(?:musttail|notail|tail)\s+)?(?:call|invoke)\b[^%@"\n]*@([A-Za-z0-9_.$]+)\(', line)
    return direct[1] if direct else None


def checked_guard_returns(body, runtime):
    blocks, name = {'': []}, ''
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        label = re.fullmatch(r'([A-Za-z0-9_.$-]+):(?:\s*;.*)?', line)
        if label:
            name = label[1]
            if name in blocks:
                return False
            blocks[name] = []
        else:
            blocks[name].append(line)
    if not blocks['']:
        del blocks['']
    if not blocks:
        return False
    pending, seen, reached = [(next(iter(blocks)), False)], set(), False
    while pending:
        name, checked = pending.pop()
        if (name, checked) in seen:
            continue
        seen.add((name, checked))
        lines = blocks.get(name)
        if not lines:
            return False
        if any(direct_ir_call(line) == runtime for line in lines):
            checked = reached = True
        end = lines[-1]
        if end.startswith('ret '):
            if not checked:
                return False
        elif end != 'unreachable':
            edges = re.findall(r'\blabel %([A-Za-z0-9_.$-]+)', end)
            if not end.startswith('br ') or not 1 <= len(edges) <= 2:
                return False
            pending.extend((edge, checked) for edge in edges)
    return reached


def recheck_ir_guard(ir, symbol, segmented):
    """Verify an entry call, not an annotation or an unrelated declaration."""
    functions = {}
    for match in re.finditer(r'^define [^\n]*@([A-Za-z0-9_.$]+)\([^\n]* \{\n', ir, re.M):
        end = ir.find('\n}', match.end())
        require(end >= 0 and match[1] not in functions, 'invalid integrity recheck IR definition')
        functions[match[1]] = ir[match.end():end]
    body = functions.get(symbol, '')
    target, offset = None, -1
    for call in re.finditer(r'^\s*(?:%[^=\n]+?=\s*)?(?:(?:musttail|notail|tail)\s+)?(?:call|invoke|callbr)\b[^\n]*', body, re.M):
        callee = direct_ir_call(call[0])
        if callee is not None and callee.startswith(('llvm.dbg.', 'llvm.lifetime.')):
            continue
        target, offset = callee, call.start()
        break
    terminator = re.search(r'^\s*(?:br|switch|ret|resume|unreachable|indirectbr)\b', body, re.M)
    require(target is not None and (terminator is None or offset < terminator.start()) and
            '!ndkp.cse.recheck.prepare' not in ir, 'missing entry integrity recheck: ' + symbol)
    runtime = 'ndkp_qseg_recheck' if segmented else 'ndkp_cse_recheck_module_v1'
    if segmented and target == runtime:
        return target
    if not segmented and re.fullmatch(r'ndkp_cse_image_recheck(?:\.[0-9]+)?', target):
        runtime = 'ndkp_cse_recheck_image_v1'
        helper = functions.get(target, '')
        calls = [line.split(';', 1)[0] for line in helper.splitlines() if direct_ir_call(line) == runtime]
        ctor = re.search(r'^@llvm\.global_ctors = [^\n]*', ir, re.M)
        require(re.search(r'^define private void @' + re.escape(target) + r'\([^\n]*!noobf !', ir, re.M) and
                len(calls) == 1 and
                re.search(r'^\s*(?:(?:musttail|notail|tail)\s+)?call\b[^%@"\n]*@' + runtime + r'\(ptr @' + re.escape(target) + r'\)', calls[0]) and
                ctor and re.search(r'i32 103, ptr @' + re.escape(target) + r'[, }]', ctor[0].split(';', 1)[0]) and
                checked_guard_returns(helper, runtime), 'invalid image integrity recheck guard: ' + symbol)
        return target
    guard = 'ndkp_cse_module_recheck_v2' if segmented else 'ndkp_cse_module_recheck'
    helper = functions.get(target, '')
    require(re.fullmatch(re.escape(guard) + r'(?:\.[0-9]+)?', target) and
            any(direct_ir_call(line) == runtime for line in helper.splitlines()) and
            (segmented or sum('load volatile ' in line for line in helper.splitlines()) == 5) and
            checked_guard_returns(helper, runtime),
            'invalid integrity recheck guard: ' + symbol)
    return target


def check_integrity_recheck(receipt, selection, native):
    expected = {}
    for row in selection['methods']:
        enabled = row.get('integrityRecheck', False)
        require(type(enabled) is bool, 'invalid selected integrity recheck')
        if enabled:
            expected[row['symbol']] = 'protected' if row['protection'] == 'vmp' else 'native'
    registration = selection.get('registrationIntegrityRecheck', False)
    require(type(registration) is bool and registration is bool(expected), 'registration integrity recheck selection differs')
    recheck = receipt.get('integrityRecheck')
    if not expected:
        require(recheck is None, 'unexpected integrity recheck receipt')
        return None
    expected['JNI_OnLoad'] = 'registration'
    segmented = receipt['segmentedData']
    runtime = 'ndkp_qseg_recheck' if segmented else 'ndkp_cse_recheck_module_v1'
    require(isinstance(recheck, dict) and recheck.get('schemaVersion') == 1 and recheck.get('runtime') == runtime and
            isinstance(recheck.get('entries'), list) and isinstance(recheck.get('irSha256'), dict),
            'missing integrity recheck receipt')
    entries, hashes = recheck['entries'], recheck['irSha256']
    require(all(isinstance(row, dict) and isinstance(row.get('symbol'), str) and
                isinstance(row.get('translationUnit'), str) and isinstance(row.get('guard'), str) for row in entries),
            'invalid integrity recheck entry')
    require(len(entries) == len(expected) and {row['symbol']: row['translationUnit'] for row in entries} == expected,
            'integrity recheck entry coverage differs')
    require(set(hashes) == set(expected.values()) and all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h)
            for h in hashes.values()), 'integrity recheck IR coverage differs')
    modules = {}
    for unit, wanted in hashes.items():
        path = native / (unit + '.ll')
        require(path.is_file(), 'missing integrity recheck IR: ' + unit)
        data = path.read_bytes()
        require(digest(data) == wanted, 'integrity recheck IR changed: ' + unit)
        if unit in ('protected', 'native'):
            require(wanted == receipt.get('irSha256' if unit == 'protected' else 'nativeIrSha256'),
                    'integrity recheck compiled IR differs: ' + unit)
        modules[unit] = data.decode('utf-8')
    for row in entries:
        require(recheck_ir_guard(modules[row['translationUnit']], row['symbol'], segmented) == row['guard'],
                'integrity recheck guard receipt differs: ' + row['symbol'])
    return {**recheck, 'validationStatus': 'passed', 'scope': 'compiler-ir-and-signed-apk-static'}


def capability(enabled, status, scope):
    return {'implemented': True, 'enabledInArtifact': enabled, 'validationStatus': status, 'scope': scope}


def capabilities(receipt, critical):
    result = {'finalApk': capability(True, 'passed', 'signed-apk-static')}
    for name, enabled in (('vmp', receipt.get('vmpMethods', 0) > 0),
                          ('nativeCse', receipt.get('nativeMethods', 0) > 0 or receipt.get('protectedStrings', 0) > 0),
                          ('segmentedData', receipt.get('segmentedData') is True),
                           ('integrityRecheck', receipt.get('integrityRecheck') is not None),
                          ('apkSignatureVerification', receipt.get('apkSignatureVerification') is True)):
        result[name] = capability(enabled, 'unverified' if enabled else 'not-applicable', 'device-runtime')
    result['criticalMethodCoverage'] = capability(None if critical is None else True,
                                                  'unverified' if critical is None else 'passed', 'signed-apk-static')
    result['buildProvenance'] = capability(None, 'unverified', 'compiler-and-plugin-origin')
    return result


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


def check_segment_coverage(receipt, segments):
    sizes = {}
    for row in segments['segments']:
        if row['kind'] == 1:
            require(type(row.get('bytes')) is int and row['bytes'] > 0 and
                    re.fullmatch('[0-9a-f]{64}', row.get('resourceSha256', '')) and
                    re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')), 'invalid VM segment identity')
            sizes[row['name']] = sizes.get(row['name'], 0) + row['bytes']
    require(sizes == receipt['methodBytecodeBytes'], 'per-method segment bytecode coverage differs')


def check_diagnostics(names):
    diagnostics = {'selection.json', 'string-selection.json', 'symbols.txt', 'native-symbols.txt', 'string-symbols.txt', 'recheck-symbols.txt',
                   'protected.cpp', 'native.cpp', 'registration.cpp', 'protected.ll', 'protected.raw.ll', 'native.ll',
                   'registration.ll', 'dex2c_runtime.ll', 'cse-runtime.ll', 'cse-runtime.raw.ll'}
    for name in names:
        require(name.replace('\\', '/').rsplit('/', 1)[-1].lower() not in diagnostics,
                'packaged build diagnostic: ' + name)


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


def verify(apks, native, generated, java, apksigner, min_sdk, report, requirements=None):
    report.unlink(missing_ok=True)
    receipt_file, selection_file = native / 'protection.json', generated / 'selection.json'
    receipt_bytes = receipt_file.read_bytes()
    receipt = json.loads(receipt_bytes)
    selection_bytes = selection_file.read_bytes()
    selection = json.loads(selection_bytes)
    methods = selection['methods']
    strings = selection.get('strings', {})
    string_count = strings.get('uniqueStrings', 0)
    requirements_bytes = None if requirements is None else requirements.read_bytes()
    critical = None if requirements_bytes is None else check_requirements(selection, json.loads(requirements_bytes))
    if not receipt['protectedMethods'] and not receipt.get('protectedStrings', 0):
        require(not methods and string_count == 0, 'zero protection receipt differs from selection')
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({'schemaVersion': 1, 'protectedMethods': 0,
            'validationStatus': 'not-applicable', 'scope': 'no-protection',
            'protectionSha256': digest(receipt_bytes), 'selectionSha256': digest(selection_bytes),
            'apks': [{'file': apk.name, 'sha256': digest(apk.read_bytes()), 'bytes': apk.stat().st_size} for apk in apks]}) + '\n'); return
    require(digest(selection_bytes) == receipt['selectionSha256'], 'selection receipt changed')
    require(len(methods) == receipt['protectedMethods'], 'method count differs')
    require(len({m['method'] for m in methods}) == len(methods) and
            len({m['symbol'] for m in methods}) == len(methods) and
            len({m['bridge'] for m in methods}) == len(methods), 'duplicate selected method, symbol or bridge')
    require(all(m['protection'] in ('vmp', 'native-cse') for m in methods), 'unknown protection policy')
    require({m['symbol'] for m in methods if m['protection'] == 'vmp'} == set(receipt['symbols']), 'VMP manifest differs')
    require({m['symbol'] for m in methods if m['protection'] == 'native-cse'} == set(receipt['nativeSymbols']), 'native manifest differs')
    check_method_receipt(receipt, selection)
    recheck = check_integrity_recheck(receipt, selection, native)
    configuration = receipt.get('configuration')
    if configuration is not None:
        require(isinstance(configuration, dict) and type(configuration.get('minSdk')) is int and
                configuration.get('minSdk') == min_sdk and configuration.get('library') == selection['library'] and
                configuration.get('segmentedData') is receipt.get('segmentedData') and
                configuration.get('apkSignatureVerification') is receipt.get('apkSignatureVerification'), 'build configuration differs')
    identity = receipt.get('compilerIdentity')
    if identity is not None:
        require(isinstance(identity, dict) and all(isinstance(identity.get(field), str) and
                re.fullmatch('[0-9a-f]{64}', identity[field]) for field in
                ('compilerSha256', 'ndkPropertiesSha256', 'linkerSha256', 'stripSha256', 'runtimeFingerprint')) and
                isinstance(identity.get('version'), str) and identity['version'], 'invalid compiler identity')
    require(string_count == receipt.get('protectedStrings', 0), 'string count differs')
    classes = generated / 'classes.jar'
    if receipt.get('classesSha256') is not None:
        require(digest(classes.read_bytes()) == receipt['classesSha256'], 'transformed classes changed')
    if string_count:
        string_selection = (generated / 'string-selection.json').read_bytes()
        require(digest(string_selection) == receipt['stringSelectionSha256'], 'string selection receipt changed')
        require(json.loads(string_selection) == strings, 'string manifests differ')
        require(receipt.get('stringSymbols') == [strings['symbol']], 'string dispatcher differs')
        require(strings['occurrences'] == len(strings['sites']) and
                {s['index'] for s in strings['sites']} == set(range(string_count)), 'string index coverage differs')
        require(receipt.get('cseHardened') and receipt.get('certificateBound') and receipt.get('selfCheckEntry') and
                receipt.get('vmpPost') and receipt.get('cseVmpMethods') == 2, 'string protection chain incomplete')
    library_path = 'lib/arm64-v8a/lib' + selection['library'] + '.so'
    asset_path = 'assets/' + selection['library'] + '.qseg'
    libraries, containers, outputs = 0, 0, []
    for apk in apks:
        data = apk.read_bytes()
        result = subprocess.run([str(java), '-jar', str(apksigner), 'verify', '--verbose', '--print-certs',
                                 '--min-sdk-version', str(min_sdk), str(apk)], capture_output=True, text=True, encoding='utf-8', errors='replace')
        require(result.returncode == 0, 'apksigner rejected ' + apk.name + ': ' + result.stdout + result.stderr)
        require(apk.read_bytes() == data, 'APK changed during signature verification: ' + apk.name)
        certificates = sorted(set(value.lower() for value in re.findall(
            r'^(?:Signer #\d+|V[0-9.]+ Signer(?: #\d+)?):? certificate SHA-256 digest: ([0-9a-fA-F]{64})$', result.stdout, re.M)))
        signer_counts = re.findall(r'^Number of signers: (\d+)\s*$', result.stdout, re.M)
        require(signer_counts == ['1'] and len(certificates) == 1 and certificates[0] == receipt['certificateSha256'], 'APK certificate differs from compiled identity')
        if receipt.get('apkSignatureVerification'):
            check_runtime_format(data, min_sdk)
        with zipfile.ZipFile(apk) as z:
            names = z.namelist(); require(len(names) == len(set(names)), 'duplicate ZIP entry')
            check_diagnostics(names)
            for entry in z.infolist():
                if entry.filename.startswith('lib/') and entry.filename.endswith('.so'):
                    binary = z.read(entry)
                    require(entry.filename.startswith('lib/arm64-v8a/') and len(binary) >= 20 and
                            binary[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', binary, 18)[0] == 183,
                            'unsupported SO ABI: ' + entry.filename)
            artifacts = []
            if library_path in names:
                binary = z.read(library_path)
                require(digest(binary) == receipt['librarySha256'], 'packaged SO differs')
                require(len(binary) == receipt['libraryBytes'], 'packaged SO size differs')
                artifacts.append({'entry': library_path, 'sha256': digest(binary), 'bytes': len(binary)})
                libraries += 1
            if asset_path in names:
                require(receipt['segmentedData'] and digest(z.read(asset_path)) == receipt['containerSha256'], 'packaged QSEG differs')
                require(z.getinfo(asset_path).file_size == receipt['containerBytes'], 'packaged QSEG size differs')
                require(z.getinfo(asset_path).compress_type == zipfile.ZIP_STORED, 'QSEG must be STORED')
                zip_entry_range(data, z.getinfo(asset_path), z.start_dir)
                artifacts.append({'entry': asset_path, 'sha256': receipt['containerSha256'], 'bytes': z.getinfo(asset_path).file_size})
                require(library_path in names, 'QSEG must share its SO APK'); containers += 1
            require(all(not name.endswith('.qseg') or name == asset_path for name in names), 'unexpected QSEG container')
        outputs.append({'file': apk.name, 'sha256': digest(data), 'bytes': len(data), 'certificateSha256': certificates[0].lower(),
                        'artifacts': artifacts})
    require(libraries >= 1 and containers == (libraries if receipt['segmentedData'] else 0), 'missing SO or container')
    if receipt['segmentedData']:
        segment_bytes = (native / 'segments.json').read_bytes()
        require(digest(segment_bytes) == receipt['segmentsReceiptSha256'], 'segment receipt changed')
        segments = json.loads(segment_bytes)
        require(segments.get('schemaVersion') == 1 and segments.get('containerSha256') == receipt['containerSha256'] and
                segments.get('containerBytes') == receipt['containerBytes'], 'segment receipt identity differs')
        check_lifetimes(receipt, segments)
        check_segment_coverage(receipt, segments)
    verify_wrappers(apks, selection, critical or ())
    evidence = {'selectionSha256': digest(selection_bytes), 'classesSha256': receipt.get('classesSha256'),
                'librarySha256': receipt['librarySha256'], 'containerSha256': receipt.get('containerSha256'),
                'segmentsReceiptSha256': receipt.get('segmentsReceiptSha256'),
                'compilerIdentity': receipt.get('compilerIdentity'), 'configuration': configuration,
                'missing': [name for name, value in (('compilerIdentity', identity), ('configuration', configuration),
                            ('criticalMethodRequirements', requirements_bytes), ('pluginArtifactProvenance', None),
                            ('deviceRuntimeValidation', None)) if value is None],
                'verifierSha256': {name: digest(Path(__file__).with_name(name).read_bytes()) for name in
                                   ('verify_dex2c_apk.py', 'dex2c_artifacts.py', 'seal_qseg.py', 'seal_cse.py')},
                'apksignerSha256': digest(apksigner.read_bytes()), 'javaSha256': digest(java.read_bytes()),
                'environment': {'python': platform.python_version(), 'host': platform.platform(), 'minSdk': min_sdk}}
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({'schemaVersion': 1, 'protectedMethods': len(methods), 'protectedStrings': string_count, 'apkSignatureVerification': receipt.get('apkSignatureVerification', False),
        'validationStatus': 'passed', 'scope': 'signed-apk-static', 'capabilities': capabilities(receipt, critical),
        'criticalMethods': critical, 'requirementsSha256': None if requirements_bytes is None else digest(requirements_bytes),
        'integrityRecheckWiring': recheck,
        'evidence': evidence, 'protectionSha256': digest(receipt_bytes), 'apks': outputs}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, action='append', required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--apksigner', type=Path, required=True)
    parser.add_argument('--min-sdk', type=int, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--requirements', type=Path, help='frozen schema 1 method/protection requirements, with optional inherited entry')
    parser.add_argument('--independent-apks', action='store_true', help='AGP APK outputs are alternative installable APKs, not a split install set')
    args = parser.parse_args()
    if args.independent_apks and len(args.apk) > 1:
        args.report.unlink(missing_ok=True)
        outputs = []
        with tempfile.TemporaryDirectory(prefix='dex2c-apk-') as directory:
            result = Path(directory) / 'verified.json'
            for apk in args.apk:
                verify([apk], args.native, args.generated, args.java, args.apksigner, args.min_sdk, result, args.requirements)
                outputs.append(json.loads(result.read_text()))
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'schemaVersion': 1, 'outputs': outputs}, indent=2) + '\n')
    else:
        verify(args.apk, args.native, args.generated, args.java, args.apksigner, args.min_sdk, args.report, args.requirements)
