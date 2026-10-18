from sigma_blindspot.sigma.ir import (
    And,
    Branch,
    Contains,
    Equals,
    LoadedRule,
    Match,
    Not,
    Or,
    Unsupported,
    fields,
    unsupported,
)

IMAGE = Match("Image", Equals("a"))
USER = Match("User", Contains("b"))


def test_lists_each_unsupported_reason_once_in_order() -> None:
    node = And((Unsupported("re"), Not(Or((Unsupported("null"), IMAGE, Unsupported("re"))))))
    assert unsupported(node) == ("re", "null")
    assert unsupported(Or((IMAGE, USER))) == ()


def test_lists_each_field_once_in_order() -> None:
    node = Or((USER, Not(And((IMAGE, Unsupported("re"), USER)))))
    assert fields(node) == ("User", "Image")


def test_a_rule_condition_is_the_or_of_its_branches() -> None:
    rule = LoadedRule(
        "rule.yml",
        "t",
        None,
        "process_creation",
        (1,),
        (),
        (Branch("#1", IMAGE), Branch("#2", USER)),
    )
    assert rule.condition == Or((IMAGE, USER))
