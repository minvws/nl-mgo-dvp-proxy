from pydantic import AnyHttpUrl

from app.config.models import (
    BaseUrl,
    DvaTargetConfig,
)


def test_dva_target_config_str_to_set_maps_value_to_list() -> None:
    assert DvaTargetConfig.str_to_set("") == set()
    assert DvaTargetConfig.str_to_set("example.com,foo.bar,acme.org") == set(
        [
            "example.com",
            "foo.bar",
            "acme.org",
        ]
    )


def test_base_url_to_string() -> None:
    raw = "https://dva.test.mgo.irealisatie.nl/"

    base_url = BaseUrl(AnyHttpUrl(raw))
    assert raw == str(base_url)
