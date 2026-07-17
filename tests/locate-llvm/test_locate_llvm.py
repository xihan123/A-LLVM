import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[2] / "scripts" / "locate_llvm.py"
SPEC = importlib.util.spec_from_file_location("locate_llvm", SCRIPT)
locate_llvm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(locate_llvm)


class LocateLlvmTest(unittest.TestCase):
    def test_parses_markdown_linked_base_revision(self):
        commit = "386af4a5c64ab75eaee2448dc38f2e34a40bfed0"
        with tempfile.TemporaryDirectory() as tmp:
            ndk = pathlib.Path(tmp)
            prebuilt = ndk / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64"
            prebuilt.mkdir(parents=True)
            (prebuilt / "AndroidVersion.txt").write_text(
                "21.0.0\nbased on r563880c\n", encoding="utf-8"
            )
            (prebuilt / "clang_source_info.md").write_text(
                f"Base revision: [{commit}](https://github.com/llvm/llvm-project/commits/{commit})\n",
                encoding="utf-8",
            )

            result = locate_llvm.locate(str(ndk), "windows-x86_64")

        self.assertEqual(result["base_commit"], commit)


if __name__ == "__main__":
    unittest.main()
