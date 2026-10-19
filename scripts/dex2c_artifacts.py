"""Read the final DEX and verify each selected implementation is a native forwarding wrapper."""
import struct
import zipfile
from pathlib import Path


class Dex:
    def __init__(self, data):
        self.data = data
        assert data[:4] == b"dex\n"
        count, offset = self.words(56, 2)
        self.strings = []
        for i in range(count):
            start = self.words(offset + 4 * i)[0]
            _, start = self.uleb(start)
            end = data.index(0, start)
            text = data[start:end].replace(b"\xc0\x80", b"\0").decode("utf-8", errors="surrogatepass")
            self.strings.append(text.encode("utf-16-le", errors="surrogatepass").decode("utf-16-le", errors="surrogatepass"))
        count, offset = self.words(64, 2)
        self.types = [self.strings[self.words(offset + 4 * i)[0]] for i in range(count)]
        count, offset = self.words(72, 2)
        self.protos = []
        for i in range(count):
            _, result, parameters = self.words(offset + 12 * i, 3)
            arguments = [] if not parameters else [self.types[struct.unpack_from("<H", data, parameters + 4 + 2 * n)[0]]
                                                   for n in range(self.words(parameters)[0])]
            self.protos.append("(" + "".join(arguments) + ")" + self.types[result])
        count, offset = self.words(88, 2)
        self.methods = []
        for i in range(count):
            owner, proto, name = struct.unpack_from("<HHI", data, offset + 8 * i)
            self.methods.append(self.types[owner][1:-1] + "." + self.strings[name] + self.protos[proto])
        self.bodies = {}
        count, offset = self.words(96, 2)
        for i in range(count):
            cursor = self.words(offset + 32 * i + 24)[0]
            if not cursor:
                continue
            sizes = []
            for _ in range(4):
                size, cursor = self.uleb(cursor)
                sizes.append(size)
            for _ in range(sizes[0] + sizes[1]):
                _, cursor = self.uleb(cursor)
                _, cursor = self.uleb(cursor)
            for size in sizes[2:]:
                method = 0
                for _ in range(size):
                    delta, cursor = self.uleb(cursor)
                    access, cursor = self.uleb(cursor)
                    code, cursor = self.uleb(cursor)
                    method += delta
                    self.bodies[self.methods[method]] = (access, code)

    def words(self, offset, count=1):
        return struct.unpack_from("<" + "I" * count, self.data, offset)

    def uleb(self, offset):
        value, shift = 0, 0
        while True:
            byte = self.data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, offset
            shift += 7
            assert shift < 35

    def forwarding_calls(self, code, synchronized):
        assert code
        count = self.words(code + 12)[0]
        instructions = struct.unpack_from("<" + "H" * count, self.data, code + 16)
        lengths = {0: 1, **{n: (1, 2, 3)[(n - 1) % 3] for n in range(1, 10)},
                   **{n: 1 for n in range(10, 19)}, 0x1a: 2, 0x1b: 3, 0x1c: 2, 0x71: 3, 0x77: 3}
        if synchronized:
            # D8 expands ACC_SYNCHRONIZED into monitor enter/exit and a catch-all rethrow.
            lengths.update({0x1d: 1, 0x1e: 1, 0x27: 1})
        cursor, calls = 0, []
        while cursor < count:
            opcode = instructions[cursor] & 255
            assert opcode in lengths, f"non-wrapper DEX opcode {opcode:#x}"
            if opcode in (0x71, 0x77):
                calls.append(self.methods[instructions[cursor + 1]])
            cursor += lengths[opcode]
        assert cursor == count
        return calls


def verify_wrappers(apk, selection):
    if not __debug__:
        raise RuntimeError("DEX verification requires Python assertions; do not use -O")
    dexes = []
    for path in ([apk] if isinstance(apk, (str, Path)) else apk):
        with zipfile.ZipFile(path) as archive:
            dexes.extend(Dex(archive.read(name)) for name in archive.namelist() if name.endswith(".dex"))
    for item in selection["methods"]:
        matches = [(dex, dex.bodies[item["method"]]) for dex in dexes if item["method"] in dex.bodies]
        assert len(matches) == 1, item["method"]
        dex, (access, code) = matches[0]
        assert not access & 0x100, item["method"]
        calls = dex.forwarding_calls(code, bool(access & 0x20000))
        assert len(calls) == 2 and calls[0] == selection["registrationCall"], calls
        assert calls[1] == item["bridge"], calls
        native = next(d.bodies[item["bridge"]] for d in dexes if item["bridge"] in d.bodies)
        assert native[0] & 0x100 and native[1] == 0
