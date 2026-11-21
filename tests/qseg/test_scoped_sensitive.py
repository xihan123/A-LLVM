"""Host checks for fixture generation and saved-stream gates; no Clang or ADB runs."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import scoped_sensitive as scoped

sys.path.insert(0, str(scoped.ROOT / "tests/cse-hardened"))
import test_seal_cse

TOKEN = "a" * 32
PAGE = 4096


def stderr_for(records, token=TOKEN):
    return b"".join(("SCOPED:" + token + ":" + name + "".join(" " + key + "=" + str(value)
                   for key, value in fields.items()) + "\n").encode("ascii") for name, fields in records)


def wait_for(code=0, signal=0, token=TOKEN):
    return (f"SCOPED:{token}:WAIT status={signal if signal else code << 8} exited={0 if signal else 1} "
            f"code={-1 if signal else code} signal={signal}\n").encode("ascii")


def prefix(mode="positive", authenticated=True):
    rows = [("CHILD_BEGIN", {"mode": mode}), ("AUTH_ATTEMPT", {"apk_verify": 0})]
    return rows + ([("AUTH_OK", {})] if authenticated else [])


def phase(name, index, observer=True, reject=False, write=False):
    size = (700003, 203)[index]; rounded = (size + PAGE - 1) // PAGE * PAGE
    common = {"phase": name, "resource": index, "begin": "0x10000000", "mapped": rounded}
    rows = []
    if observer:
        rows.append(("POISON", {**common, "bytes": size, "padding": rounded-size, "value": 165}))
    rows.append(("ACQUIRED", {**common, "bytes": size, "padding": rounded-size,
                              "padding_value": 165 if observer else 0}))
    if name == "concurrent":
        rows += [("NESTED", {"leases": 3, "owner_live": 1}),
                 ("CONCURRENT", {"borrowers": 8, "same_pointer": 1, "owner_live_after_release": 1})]
    if write:
        return rows + [("ATTEMPT", {"mode": "write"})]
    rows.append(("RELEASE_ATTEMPT", common.copy()))
    if observer:
        if reject:
            rows.append(("INJECT_PADDING", {"offset": rounded-1, "value": 123}))
        rows.append(("ZERO_SCAN", {**common, "checked": rounded, "padding": rounded-size,
                                    "nonzero": 1 if reject else 0, "first": rounded-1 if reject else rounded,
                                    "value": 123 if reject else 0}))
        if reject:
            return rows + [("REJECT_NONZERO", {"real_unmaps": 0, "code": 123})]
        rows.append(("REAL_UNMAP", {**common, "result": 0}))
    return rows + [("ABSENT", common.copy())]


def positive(observer=True):
    rows = prefix()
    for name, index in (("concurrent", 0), ("reload", 0), ("mixed", 1), ("mixed-reload", 1)):
        rows += phase(name, index, observer)
    return rows + [("MIXED", {"separate": 1, "ordinary_pinned": PAGE, "ordinary_peak": PAGE,
                              "copy_bytes": 203, "copy_wiped": 1}),
                   ("COMPLETE", {"observer": int(observer), "releases": 4, "scans": 4 if observer else 0,
                                  "real_unmaps": 4 if observer else 0, "page": PAGE})]


class StreamTests(unittest.TestCase):
    def validate(self, rows, mode="positive", observer=True, code=0, signal=0, failure=None):
        return scoped.validate_run(wait_for(code, signal), stderr_for(rows), TOKEN, mode, observer, PAGE, failure)

    def test_pristine_and_observed_complete_streams(self):
        for observer in (False, True):
            with self.subTest(observer=observer):
                self.assertEqual(self.validate(positive(observer), observer=observer)["exitCode"], 0)

    def test_full_page_scan_padding_and_real_unmap_are_required(self):
        rows = positive()
        for name, key, value in (("POISON", "value", 0), ("ACQUIRED", "padding_value", 0),
                                 ("ZERO_SCAN", "checked", 700003), ("ZERO_SCAN", "padding", 0),
                                 ("ZERO_SCAN", "nonzero", 1), ("REAL_UNMAP", "result", -1)):
            mutated = copy.deepcopy(rows)
            next(fields for event, fields in mutated if event == name)[key] = value
            with self.subTest(event=name, key=key), self.assertRaises(ValueError):
                self.validate(mutated)
        for name in ("NESTED", "CONCURRENT", "ZERO_SCAN", "REAL_UNMAP", "ABSENT", "COMPLETE"):
            mutated = copy.deepcopy(rows); del mutated[next(i for i, (event, _) in enumerate(mutated) if event == name)]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.validate(mutated)

    def test_scan_and_absence_are_bound_to_the_acquired_interval(self):
        for event in ("RELEASE_ATTEMPT", "ZERO_SCAN", "REAL_UNMAP", "ABSENT"):
            rows = positive(); next(fields for name, fields in rows if name == event)["begin"] = "0x10001000"
            with self.subTest(event=event), self.assertRaises(ValueError):
                self.validate(rows)

    def test_extra_duplicate_fields_and_foreign_token_fail(self):
        rows = positive(); data = stderr_for(rows)
        for changed in (data + stderr_for([rows[-1]]), data.replace(b"nonzero=0", b"nonzero=0 nonzero=0", 1),
                        data.replace(TOKEN.encode(), b"b" * 32, 1)):
            with self.subTest(data=changed), self.assertRaises(ValueError):
                scoped.validate_run(wait_for(), changed, TOKEN, "positive", True, PAGE)

    def test_padding_control_requires_exact_scan_and_exit(self):
        rows = prefix("reject-padding") + phase("negative", 0, reject=True)
        self.assertEqual(self.validate(rows, "reject-padding", code=123)["exitCode"], 123)
        for code in (0, 127):
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.validate(rows, "reject-padding", code=code)
        next(fields for name, fields in rows if name == "ZERO_SCAN")["first"] = 700003
        with self.assertRaises(ValueError):
            self.validate(rows, "reject-padding", code=123)

    def test_write_rejection_needs_authenticated_readonly_borrow(self):
        rows = prefix("write") + phase("negative", 0, observer=False, write=True)
        self.assertEqual(self.validate(rows, "write", observer=False, signal=11)["signal"], 11)
        for changed in (rows[1:], [row for row in rows if row[0] != "ACQUIRED"]):
            with self.assertRaises(ValueError):
                self.validate(changed, "write", observer=False, signal=11)

    def test_enomem_requires_real_warmup_and_exact_injected_fault(self):
        rows = prefix("enomem") + phase("warmup", 1) + [("ATTEMPT", {"mode": "enomem"}),
                ("MMAP_ENOMEM", {"phase": "enomem", "bytes": 700003, "hits": 1, "errno": 12})]
        self.assertEqual(self.validate(rows, "enomem", code=127)["exitCode"], 127)
        for key, value in (("hits", 0), ("bytes", 203), ("errno", 11)):
            mutated = copy.deepcopy(rows); mutated[-1][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(mutated, "enomem", code=127)

    def test_initial_and_last_chunk_auth_failures_have_distinct_gates(self):
        initial = prefix("auth", authenticated=False)
        last = prefix("auth") + [("ATTEMPT", {"mode": "auth"})]
        self.assertEqual(self.validate(initial, "auth", False, 127, failure="initialization")["exitCode"], 127)
        self.assertEqual(self.validate(last, "auth", False, 127, failure="last-chunk")["exitCode"], 127)
        for rows, failure in ((last, "initialization"), (initial, "last-chunk")):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.validate(rows, "auth", False, 127, failure=failure)


class FixtureTests(unittest.TestCase):
    def test_old_and_v3_apksigner_labels_preserve_exact_single_certificate_gate(self):
        certificate = b"host-certificate"; digest = hashlib.sha256(certificate).hexdigest().encode("ascii")
        for label in (b"Signer #1", b"V3.0 Signer:", b"V3.0 Signer #1:"):
            stdout = b"Number of signers: 1\r\n" + label + b" certificate SHA-256 digest: " + digest + b"\r\n"
            scoped.verify_certificate(stdout, certificate)
            for changed in (stdout.replace(b"signers: 1", b"signers: 2"), stdout.replace(digest, b"0" * 64),
                            stdout + b"V3.0 Signer: certificate SHA-256 digest: " + b"0" * 64 + b"\n"):
                with self.subTest(label=label), self.assertRaises(ValueError):
                    scoped.verify_certificate(changed, certificate)

    def test_staging_and_rx_descriptors_bind_the_same_resource_bytes(self):
        resources = scoped.resources()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); scoped.stage_fixture(output, resources)
            self.assertEqual(scoped.qseg.read_stages([output / "staging"]), resources)
            assembly = (output / "scoped_refs.S").read_text(encoding="utf-8")
            self.assertIn('.section .text.ndkp.qseg.refs,"ax",%progbits', assembly)
            descriptors = [bytes(map(int, line[6:].split(","))) for line in assembly.splitlines() if line.startswith(".byte ")]
            self.assertEqual(descriptors, [i + struct.pack("<II", len(raw), kind) for i, kind, raw, _ in resources])
            self.assertTrue(all(all(raw) for _, _, raw, _ in resources))

    def test_last_native_chunk_changes_without_changing_authenticated_index_or_rx(self):
        resources = scoped.resources(); certificate = b"host-scoped-certificate"
        header = scoped.qseg.prepare(resources, scoped.ASSET, certificate)
        image = bytearray(test_seal_cse.elf(header)); struct.pack_into("<I", image, 64 + 2 * 56 + 4, 4)
        library, container, _ = scoped.qseg.pack(image, resources)
        changed, payload, binding = scoped.tamper_last_chunk(library, container, certificate, resources)
        self.assertEqual(binding["chunk"], 10); self.assertTrue(binding["outerDigestUpdated"])
        differences = [i for i, (before, after) in enumerate(zip(container, payload)) if before != after]
        self.assertEqual(differences, [binding["offset"]])
        index_end = 32 + scoped.qseg.u32(container, 12)
        self.assertEqual(container[:index_end], payload[:index_end])
        self.assertEqual(scoped.qseg.Elf(library).code_hash(), scoped.qseg.Elf(changed).code_hash())
        _, position = scoped.qseg.locate_image(changed)
        self.assertEqual(changed[position + 384:position + 416], hashlib.sha256(payload).digest())
        self.assertLess(binding["offset"], len(container) - 203)
        with self.assertRaisesRegex(ValueError, "authentication"):
            scoped.qseg.unpack(changed, payload, certificate)

    def test_stale_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"; self.assertEqual(scoped.fresh_output(output), output)
            (output / "evidence").write_bytes(b"old")
            with self.assertRaises(ValueError):
                scoped.fresh_output(output)


if __name__ == "__main__":
    unittest.main()
