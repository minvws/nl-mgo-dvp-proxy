from app.authentication.exceptions import RequestValidationException


class MedMijOAuthCallbackRequestValidator:
    def validate_query_params(
        self,
        error: int | None,
        code: str | None,
        state: str | None,
    ) -> None:
        if error is not None:
            return

        if code is None:
            raise RequestValidationException(
                detail=[
                    {
                        "loc": ["query", "code"],
                        "msg": "Field required",
                        "type": "value_error.missing",
                    }
                ]
            )
        if state is None:
            raise RequestValidationException(
                detail=[
                    {
                        "loc": ["query", "state"],
                        "msg": "Field required",
                        "type": "value_error.missing",
                    }
                ]
            )
