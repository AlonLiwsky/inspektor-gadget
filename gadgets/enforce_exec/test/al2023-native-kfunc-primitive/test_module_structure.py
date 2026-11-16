import importlib.util
import pathlib
import struct
import unittest

spec = importlib.util.spec_from_file_location("checker", pathlib.Path(__file__).with_name("check-module.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class RegistrationTest(unittest.TestCase):
    def test_good(self):
        checker.validate(struct.pack("<4I", 1, 1, 25, 0x30), "[25] FUNC 'ig_capture_pending_argv' type_id=13 linkage=static\n")

    def test_reject_incomplete_or_wrong_registration(self):
        dump = "[25] FUNC 'ig_capture_pending_argv' type_id=13 linkage=static\n"
        for values in [(0, 1, 0, 0x30), (1, 1, 0, 0x30), (2, 1, 25, 0x30), (1, 0, 25, 0x30), (1, 1, 26, 0x30), (1, 1, 25, 0x10)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                checker.validate(struct.pack("<4I", *values), dump)
        for blob in [b"", bytes(16), struct.pack("<4I", 1, 1, 25, 0x30) + bytes(8)]:
            with self.assertRaises(ValueError):
                checker.validate(blob, dump)
        with self.assertRaises(ValueError):
            checker.validate(struct.pack("<4I", 1, 1, 25, 0x30), "")


class CanonicalArgumentTest(unittest.TestCase):
    base = "[1] STRUCT 'linux_binprm' size=408 vlen=0\n"
    split = ("[2] PTR '(anon)' type_id=1\n"
             "[3] FUNC_PROTO '(anon)' ret_type_id=0 vlen=3\n"
             "\t'bprm' type_id=2\n\t'output' type_id=2\n\t'output__sz' type_id=2\n"
             "[4] FUNC 'ig_capture_pending_argv' type_id=3 linkage=static\n")

    def test_canonical(self):
        checker.validate_arg0(self.base, self.base + self.split)

    def test_same_name_and_layout_not_identity(self):
        duplicate = "[5] STRUCT 'linux_binprm' size=408 vlen=0\n"
        with self.assertRaisesRegex(ValueError, "canonical"):
            checker.validate_arg0(self.base, self.base + self.split.replace("PTR '(anon)' type_id=1", "PTR '(anon)' type_id=5") + duplicate)

    def test_missing_base_type(self):
        with self.assertRaises(ValueError):
            checker.validate_arg0("", self.base + self.split)


if __name__ == "__main__":
    unittest.main()
