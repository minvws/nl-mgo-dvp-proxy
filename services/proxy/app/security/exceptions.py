class CouldNotDecryptPayload(Exception):
    @staticmethod
    def because_failed_to_decrypt_ciphertext() -> "CouldNotDecryptPayload":
        return CouldNotDecryptPayload("Failed to decrypt ciphertext")
