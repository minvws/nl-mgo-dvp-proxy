class WhitelistError(Exception):
    @staticmethod
    def because_hostname_not_whitelisted(hostname: str) -> "WhitelistError":
        return WhitelistError(f"Hostname is not whitelisted: {hostname}")

    @staticmethod
    def because_unexpected_cache_state() -> "WhitelistError":
        return WhitelistError("Unexpected cache state")
