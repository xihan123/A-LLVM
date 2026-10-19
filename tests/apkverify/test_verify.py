"""Real signatures, independently computed APK digests, and malformed signed records.

Requires a built apkverify_probe, JDK 21 and SDK apksigner.jar. --serial additionally
tests the same files with an Android probe, without installing any APK.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
V2, V3 = 0x7109871A, 0xF05368C0


def lp(data):
    return struct.pack('<I', len(data)) + data


def run(command):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed: {result.stdout}\n{result.stderr}')
    return result.stdout


class VerifyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = ARGS.work.resolve()
        cls.out.mkdir(parents=True, exist_ok=True)
        cls.java = ARGS.java / 'bin/java.exe' if (ARGS.java / 'bin/java.exe').exists() else ARGS.java / 'bin/java'
        cls.keytool = cls.java.with_name('keytool' + cls.java.suffix)
        run([cls.java.with_name('javac' + cls.java.suffix), '-d', cls.out, ROOT / 'tests/apkverify/SignFixture.java'])
        cls.keys = {}
        for kind, key_options in [('rsa', ['-keyalg', 'RSA', '-keysize', '2048']), ('ec', ['-keyalg', 'EC', '-groupname', 'secp256r1'])]:
            key = cls.out / f'{kind}.p12'
            if not key.exists():
                run([cls.keytool, '-genkeypair', '-keystore', key, '-storetype', 'PKCS12', '-storepass', 'android',
                     '-keypass', 'android', '-alias', 'test', '-dname', 'CN=apkverify disposable test', '-validity', '3650', *key_options])
            cls.keys[kind] = key
        unsigned = cls.out / 'unsigned.apk'
        manifest = cls.out / 'AndroidManifest.xml'
        manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.ndkp.verify"><application android:hasCode="false"/></manifest>')
        platform = max((ARGS.sdk / 'platforms').glob('android-*'), key=lambda p: int(p.name.split('-')[1]) if p.name.split('-')[1].isdigit() else 0)
        aapt = ARGS.sdk / 'build-tools' / ARGS.build_tools / ('aapt2.exe' if cls.java.suffix else 'aapt2')
        manifest_apk = cls.out / 'manifest.apk'
        run([aapt, 'link', '-o', manifest_apk, '--manifest', manifest, '-I', platform / 'android.jar', '--min-sdk-version', '26', '--target-sdk-version', '28'])
        with zipfile.ZipFile(unsigned, 'w') as z:
            with zipfile.ZipFile(manifest_apk) as source:
                z.writestr('AndroidManifest.xml', source.read('AndroidManifest.xml'))
            z.writestr('classes.dex', b'dex fixture' + b'X' * (2 * 1024 * 1024 + 71))
            z.writestr('lib/arm64-v8a/libtest.so', b'ELF fixture')
            z.writestr('assets/resource', b'protected resource')
            z.comment = b'comment with fake PK\x05\x06 marker'
        cls.unsigned = unsigned.read_bytes()
        cls.eocd = len(cls.unsigned) - 22 - len(b'comment with fake PK\x05\x06 marker')
        cls.cd = struct.unpack_from('<I', cls.unsigned, cls.eocd + 16)[0]
        cls.signer = ARGS.sdk / 'build-tools' / ARGS.build_tools / 'lib/apksigner.jar'
        cls.results = []
        if ARGS.serial:
            cls.adb = ARGS.sdk / 'platform-tools' / ('adb.exe' if (ARGS.sdk / 'platform-tools/adb.exe').exists() else 'adb')
            cls.remote = '/data/local/tmp/ndkp-apkverify-test'
            run([cls.adb, '-s', ARGS.serial, 'shell', 'mkdir', '-p', cls.remote])
            run([cls.adb, '-s', ARGS.serial, 'push', ARGS.device_probe, cls.remote + '/probe'])
            run([cls.adb, '-s', ARGS.serial, 'shell', 'chmod', '700', cls.remote + '/probe'])

    @classmethod
    def tearDownClass(cls):
        (cls.out / 'results.json').write_text(json.dumps(cls.results, indent=2) + '\n')
        if ARGS.serial:
            # This fixed, test-owned directory contains only fixtures created above.
            run([cls.adb, '-s', ARGS.serial, 'shell', 'rm', '-r', cls.remote])

    def signed(self, algorithm=0x0103, scheme=V2, attrs=b'', extra_signer=False,
               digest_id=None, public_mismatch=False, sdk=(28, 0x7FFFFFFF), signed_sdk=None):
        sha = 'sha512' if algorithm in (0x0102, 0x0104, 0x0202) else 'sha256'
        chunks = []
        for section in (self.unsigned[:self.cd], self.unsigned[self.cd:self.eocd], self.unsigned[self.eocd:]):
            for i in range(0, len(section), 1024 * 1024):
                chunk = section[i:i + 1024 * 1024]
                chunks.append(hashlib.new(sha, b'\xa5' + struct.pack('<I', len(chunk)) + chunk).digest())
        digest = hashlib.new(sha, b'\x5a' + struct.pack('<I', len(chunks)) + b''.join(chunks)).digest()
        key = self.keys['ec' if algorithm in (0x0201, 0x0202) else 'rsa']
        data_file, sig_file = self.out / 'signed-data', self.out / 'signature'
        # Export the certificate independently of the signature helper.
        cert_file = self.out / 'cert.der'
        run([self.keytool, '-exportcert', '-keystore', key, '-storepass', 'android', '-alias', 'test', '-file', cert_file])
        cert = cert_file.read_bytes()
        signed = lp(lp(struct.pack('<I', algorithm if digest_id is None else digest_id) + lp(digest))) + lp(lp(cert))
        if scheme == V3:
            signed += struct.pack('<II', *(signed_sdk or sdk))
        signed += lp(attrs)
        data_file.write_bytes(signed)
        name = 'RSASSA-PSS' if algorithm in (0x0101, 0x0102) else ('SHA512' if sha == 'sha512' else 'SHA256') + ('withECDSA' if key == self.keys['ec'] else 'withRSA')
        run([self.java, '-cp', self.out, 'SignFixture', key, data_file, sig_file, name, 'SHA-512' if sha == 'sha512' else 'SHA-256'])
        public = Path(str(sig_file) + '.pub').read_bytes()
        if public_mismatch:
            public = public[:-1] + bytes([public[-1] ^ 1])
        signatures = lp(struct.pack('<I', algorithm) + lp(sig_file.read_bytes()))
        signer = lp(signed) + (struct.pack('<II', *sdk) if scheme == V3 else b'') + lp(signatures) + lp(public)
        value = lp(lp(signer) * (2 if extra_signer else 1))
        pair = struct.pack('<QI', len(value) + 4, scheme) + value
        length = struct.pack('<Q', len(pair) + 24)
        block = length + pair + length + b'APK Sig Block 42'
        apk = bytearray(self.unsigned[:self.cd] + block + self.unsigned[self.cd:])
        struct.pack_into('<I', apk, self.eocd + len(block) + 16, self.cd + len(block))
        return apk, hashlib.sha256(cert).hexdigest()

    def probe(self, name, data, cert, valid, api=37, oracle=False):
        apk = self.out / f'{name}.apk'; apk.write_bytes(data)
        result = subprocess.run([str(ARGS.probe.resolve()), str(apk), cert, str(api)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if valid else 1, name + ': ' + result.stdout + result.stderr)
        device = None
        if ARGS.serial:
            run([self.adb, '-s', ARGS.serial, 'push', apk, self.remote + '/input.apk'])
            remote = subprocess.run([str(self.adb), '-s', ARGS.serial, 'shell', self.remote + '/probe', self.remote + '/input.apk', cert, str(api)], capture_output=True, text=True)
            self.assertEqual(remote.returncode, result.returncode, name + ': ' + remote.stdout + remote.stderr)
            device = remote.stdout.strip()
        if oracle:
            run([self.java, '-jar', self.signer, 'verify', '--min-sdk-version', max(28, api) if name.startswith('v3') else 26, apk])
        self.results.append({'case': name, 'apkSha256': hashlib.sha256(data).hexdigest(), 'valid': valid,
                             'host': result.stdout.strip(), 'device': device})

    def test_all_signature_algorithms(self):
        for alg in (0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202):
            with self.subTest(algorithm=alg):
                data, cert = self.signed(alg)
                # SDK apksig requests obsolete JCA PSS aliases absent from stock JDK 21.
                self.probe(f'algorithm-{alg:x}', data, cert, True, oracle=alg not in (0x0101, 0x0102))

    def test_sdk_apksigner_output(self):
        output = self.out / 'sdk-signed.apk'
        run([self.java, '-jar', self.signer, 'sign', '--ks', self.keys['rsa'], '--ks-pass', 'pass:android',
             '--min-sdk-version', '26', '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
             '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false', '--out', output, self.out / 'unsigned.apk'])
        _, cert = self.signed()
        self.probe('sdk-v2-v3', output.read_bytes(), cert, True, oracle=True)

    def test_authenticated_invalid_records(self):
        options = {
            'multiple-signers': {'extra_signer': True},
            'algorithm-mismatch': {'digest_id': 0x0104},
            'unsupported-algorithm': {'algorithm': 0x0301},
            'public-key-mismatch': {'public_mismatch': True},
            'stripped-v3': {'attrs': lp(struct.pack('<II', 0xBEEFF00D, 3))},
            'rotation': {'scheme': V3, 'attrs': lp(struct.pack('<I', 0x3BA06F8C))},
            'v31-rotation': {'scheme': V3, 'attrs': lp(struct.pack('<II', 0x559F8B02, 33))},
            'sdk-mismatch': {'scheme': V3, 'signed_sdk': (29, 0x7FFFFFFF)},
            'sdk-range': {'scheme': V3, 'sdk': (28, 30)},
            'malformed-attrs': {'attrs': struct.pack('<I', 100)},
        }
        for name, settings in options.items():
            with self.subTest(case=name):
                data, cert = self.signed(**settings); self.probe(name, data, cert, False)

    def test_v3_and_api26(self):
        data, cert = self.signed(scheme=V3)
        self.probe('v3-only', data, cert, True, oracle=True)
        self.probe('v3-api26', data, cert, False, api=26)
        data, cert = self.signed()
        self.probe('v2-api26', data, cert, True, api=26)

    def test_mutations(self):
        original, cert = self.signed()
        self.probe('wrong-certificate', original, '00' * 32, False)
        self.probe('unsigned', self.unsigned, cert, False)
        for name, at in [('dex', 100), ('so', original.index(b'ELF fixture')),
                         ('resource', original.index(b'protected resource')), ('signature', self.cd + 40),
                         ('length', self.cd), ('central-directory', self.cd + len(original) - len(self.unsigned) + 16)]:
            data = bytearray(original); data[at] ^= 1
            self.probe('tampered-' + name, data, cert, False)
        self.probe('truncated', original[:-1], cert, False)
        self.probe('empty', b'', cert, False)

    def test_copied_block_and_excluded_schemes(self):
        original, cert = self.signed()
        source = self.unsigned
        try:
            self.unsigned = source.replace(b'protected resource', b'changed!! resource')
            changed, _ = self.signed()
        finally:
            self.unsigned = source
        block_size = len(original) - len(source)
        copied = changed[:self.cd] + original[self.cd:self.cd + block_size] + changed[self.cd + block_size:]
        self.probe('copied-signing-block', copied, cert, False)
        v31 = bytearray(original)
        struct.pack_into('<I', v31, self.cd + 16, 0x1B93AD61)
        self.probe('v31-block', v31, cert, False)
        signed = self.out / 'v1-only.apk'
        run([self.java, '-jar', self.signer, 'sign', '--ks', self.keys['rsa'], '--ks-pass', 'pass:android',
             '--min-sdk-version', '26', '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'false',
             '--v3-signing-enabled', 'false', '--out', signed, self.out / 'unsigned.apk'])
        self.probe('v1-only', signed.read_bytes(), cert, False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--build-tools', default='37.0.0')
    parser.add_argument('--work', type=Path, default=ROOT / 'build/apkverify-tests')
    parser.add_argument('--serial')
    parser.add_argument('--device-probe', type=Path)
    ARGS = parser.parse_args()
    if bool(ARGS.serial) != bool(ARGS.device_probe):
        parser.error('--serial and --device-probe must be supplied together')
    unittest.main(argv=['test_verify'], verbosity=2)
