import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sigma_blindspot.sysmon.conditions import Operator, fold, split_values

LSASS = "C:\\Windows\\System32\\lsass.exe"

ascii_texts = st.text(alphabet=string.ascii_letters + "\\;. ", max_size=6)
any_texts = st.text(max_size=6)
items = st.text(alphabet="aAbB\\. ", min_size=1, max_size=3)

COMPLEMENTS = [
    (Operator.IS, Operator.IS_NOT),
    (Operator.CONTAINS, Operator.EXCLUDES),
    (Operator.CONTAINS_ALL, Operator.EXCLUDES_ANY),
    (Operator.CONTAINS_ANY, Operator.EXCLUDES_ALL),
    (Operator.BEGIN_WITH, Operator.NOT_BEGIN_WITH),
    (Operator.END_WITH, Operator.NOT_END_WITH),
]

SINGLE_VALUE_EQUIVALENTS = [
    (Operator.IS_ANY, Operator.IS),
    (Operator.CONTAINS_ANY, Operator.CONTAINS),
    (Operator.CONTAINS_ALL, Operator.CONTAINS),
    (Operator.EXCLUDES_ANY, Operator.EXCLUDES),
    (Operator.EXCLUDES_ALL, Operator.EXCLUDES),
]


@pytest.mark.parametrize(
    ("operator", "field", "value", "expected"),
    [
        (Operator.IS, LSASS, "c:\\windows\\system32\\LSASS.EXE", True),
        (Operator.IS, LSASS, "lsass.exe", False),
        (Operator.IS, "cmd.exe", " cmd.exe", False),
        (Operator.IS_ANY, "cmd.exe", "powershell.exe;CMD.EXE", True),
        (Operator.IS_ANY, "cmd.exe", "powershell.exe;pwsh.exe", False),
        (Operator.IS_ANY, "", "a;;b", False),
        (Operator.IS_NOT, "cmd.exe", "CMD.EXE", False),
        (Operator.IS_NOT, "cmd.exe", "pwsh.exe", True),
        (Operator.CONTAINS, "a -EncodedCommand b", "-encodedcommand", True),
        (Operator.CONTAINS, "a -enc b", "-encodedcommand", False),
        (Operator.CONTAINS_ANY, "x -enc y", "-encodedcommand;-ENC", True),
        (Operator.CONTAINS_ANY, "xyz", "a;", False),
        (Operator.CONTAINS_ALL, "a b c", "A;C", True),
        (Operator.CONTAINS_ALL, "a b", "a;c", False),
        (Operator.EXCLUDES, "abc", "d", True),
        (Operator.EXCLUDES, "abc", "B", False),
        (Operator.EXCLUDES_ANY, "abc", "a;d", True),
        (Operator.EXCLUDES_ANY, "abc", "a;B", False),
        (Operator.EXCLUDES_ALL, "abc", "d;e", True),
        (Operator.EXCLUDES_ALL, "abc", "d;A", False),
        (Operator.BEGIN_WITH, LSASS, "c:\\windows\\", True),
        (Operator.BEGIN_WITH, LSASS, "c:\\users\\", False),
        (Operator.END_WITH, LSASS, "\\LSASS.EXE", True),
        (Operator.END_WITH, LSASS, "\\cmd.exe", False),
        (Operator.NOT_BEGIN_WITH, LSASS, "c:\\users\\", True),
        (Operator.NOT_BEGIN_WITH, LSASS, "C:\\WINDOWS", False),
        (Operator.NOT_END_WITH, LSASS, ".EXE", False),
        (Operator.NOT_END_WITH, LSASS, ".dll", True),
        (Operator.LESS_THAN, "a", "B", True),
        (Operator.LESS_THAN, "b", "A", False),
        (Operator.LESS_THAN, "10", "9", True),
        (Operator.MORE_THAN, "9", "10", True),
        (Operator.MORE_THAN, "a", "A", False),
        (Operator.IMAGE, LSASS, "lsass.exe", True),
        (Operator.IMAGE, LSASS, "C:\\WINDOWS\\system32\\lsass.exe", True),
        (Operator.IMAGE, LSASS, "system32\\lsass.exe", False),
        (Operator.IMAGE, LSASS, "lsass", False),
        (Operator.IMAGE, "lsass.exe", "LSASS.exe", True),
    ],
)
def test_operator_matches_documented_examples(
    operator: Operator, field: str, value: str, expected: bool
) -> None:
    assert operator.matches(field, value) is expected


def test_every_documented_condition_is_an_operator() -> None:
    assert len(Operator) == 16


def test_split_values_ignores_empty_items() -> None:
    assert split_values(";a;;b c;") == ("a", "b c")


def test_fold_uses_the_unicode_lower_case_mapping() -> None:
    assert fold("C:\\Windows\\É") == "c:\\windows\\é"
    assert not Operator.IS.matches("Straße", "STRASSE")


@pytest.mark.parametrize(("positive", "negative"), COMPLEMENTS)
@given(field=any_texts, value=any_texts)
def test_negated_operators_are_complements(
    positive: Operator, negative: Operator, field: str, value: str
) -> None:
    assert negative.matches(field, value) is not positive.matches(field, value)


@pytest.mark.parametrize("operator", list(Operator))
@given(field=ascii_texts, value=ascii_texts)
def test_operators_ignore_ascii_case(operator: Operator, field: str, value: str) -> None:
    expected = operator.matches(field, value)
    assert operator.matches(field.upper(), value) is expected
    assert operator.matches(field, value.swapcase()) is expected


@pytest.mark.parametrize(("listed", "scalar"), SINGLE_VALUE_EQUIVALENTS)
@given(field=any_texts, value=st.text(min_size=1, max_size=6).filter(lambda text: ";" not in text))
def test_single_item_lists_behave_like_scalar_operators(
    listed: Operator, scalar: Operator, field: str, value: str
) -> None:
    assert listed.matches(field, value) is scalar.matches(field, value)


@given(field=any_texts, values=st.lists(items, min_size=1, max_size=4))
def test_list_operators_combine_their_items(field: str, values: list[str]) -> None:
    joined = ";".join(values)
    assert Operator.IS_ANY.matches(field, joined) is any(
        Operator.IS.matches(field, value) for value in values
    )
    assert Operator.CONTAINS_ANY.matches(field, joined) is any(
        Operator.CONTAINS.matches(field, value) for value in values
    )
    assert Operator.CONTAINS_ALL.matches(field, joined) is all(
        Operator.CONTAINS.matches(field, value) for value in values
    )


@given(directory=any_texts, name=st.text(min_size=1, max_size=6).filter(lambda t: "\\" not in t))
def test_image_matches_full_path_and_bare_name(directory: str, name: str) -> None:
    path = f"{directory}\\{name}"
    assert Operator.IMAGE.matches(path, name)
    assert Operator.IMAGE.matches(path, path)


@given(field=any_texts, value=any_texts)
def test_exactly_one_of_less_more_or_equal_holds(field: str, value: str) -> None:
    outcomes = [
        Operator.LESS_THAN.matches(field, value),
        Operator.MORE_THAN.matches(field, value),
        Operator.IS.matches(field, value),
    ]
    assert outcomes.count(True) == 1
    assert Operator.LESS_THAN.matches(field, value) is Operator.MORE_THAN.matches(value, field)
