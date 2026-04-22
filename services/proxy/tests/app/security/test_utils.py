from pytest import mark

from app.security.utils import LogSanitizer


class TestLogSanitizer:
    def test_printable_ascii_is_unchanged(self) -> None:
        s = "abcXYZ0123-._~"

        assert LogSanitizer.sanitize(s) == s

    @mark.parametrize(
        "raw, expected",
        [
            ("a\nb", r"a\nb"),
            ("a\rb", r"a\rb"),
            ("a\tb", r"a\tb"),
            ("\n\r\t", r"\n\r\t"),
        ],
    )
    def test_common_control_chars_are_escaped(self, raw: str, expected: str) -> None:
        assert LogSanitizer.sanitize(raw) == expected

    def test_non_printable_chars_are_unicode_escaped(
        self,
    ) -> None:
        raw = "a" + "\x00" + "b" + "\x1b" + "c"

        assert LogSanitizer.sanitize(raw) == r"a\x00b\x1bc"

    def test_non_ascii_is_unicode_escaped(
        self,
    ) -> None:
        raw = "café"

        assert LogSanitizer.sanitize(raw) == r"caf\xe9"

    def test_does_not_double_escape_backslashes(self) -> None:
        raw = r"a\b"

        assert LogSanitizer.sanitize(raw) == raw
