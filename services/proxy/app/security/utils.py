from string import printable


class LogSanitizer:
    @staticmethod
    def sanitize(value: str) -> str:
        value = value.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
        value = "".join(
            ch if ch in printable and ch not in "\x0b\x0c" else f"\\x{ord(ch):02x}"
            for ch in value
        )

        return value
