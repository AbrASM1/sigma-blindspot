import z3
from hypothesis import assume, given
from hypothesis import strategies as st
from strategies import literals

from sigma_blindspot.prover.languages import Languages, Literal
from sigma_blindspot.prover.witness import MAX_REQUIRED, applies, exact_witness
from sigma_blindspot.sigma.evaluate import pattern_matches
from sigma_blindspot.sigma.ir import Contains, Equals, Glob, Prefix, Suffix, Wildcard

simple_patterns = st.one_of(
    *(st.builds(kind, literals) for kind in (Equals, Prefix, Suffix, Contains))
)
literal_sets = st.lists(st.tuples(simple_patterns, st.booleans()), min_size=1, max_size=6)


def z3_finds(chosen: list[Literal]) -> bool:
    context = z3.Context()
    languages = Languages(context)
    solver = z3.Solver(ctx=context)
    value = z3.String("value", context)
    solver.add(z3.InRe(value, z3.Intersect(languages.language(chosen), languages.folded)))
    return bool(solver.check() == z3.sat)


def satisfies(chosen: list[Literal], value: str) -> bool:
    folded = not any("A" <= character <= "Z" for character in value)
    return folded and all(pattern_matches(pattern, value) is holds for pattern, holds in chosen)


@given(chosen=literal_sets)
def test_the_exact_witness_agrees_with_z3(chosen: list[Literal]) -> None:
    assert (exact_witness(chosen) is not None) is z3_finds(chosen)


@given(chosen=literal_sets)
def test_every_exact_witness_satisfies_its_literals(chosen: list[Literal]) -> None:
    found = exact_witness(chosen)
    assume(found is not None)
    assert found is not None and satisfies(chosen, found)


def test_incompatible_endings_have_no_witness() -> None:
    assert exact_witness([(Suffix(".bat"), True), (Suffix(".txt"), True)]) is None
    assert exact_witness([(Prefix("c:\\"), True), (Prefix("d:\\"), True)]) is None


def test_a_required_part_containing_a_forbidden_part_has_no_witness() -> None:
    assert exact_witness([(Contains("\\temp\\"), True), (Contains("temp"), False)]) is None


def test_forbidden_parts_are_avoided_around_required_ones() -> None:
    chosen: list[Literal] = [
        (Contains("control\\wmi\\autologger\\senseeventlog"), True),
        (Suffix("\\enablemodulelogging"), True),
        (Contains("\\control\\wmi\\autologger\\"), False),
        (Prefix("hklm\\software"), False),
    ]
    found = exact_witness(chosen)
    assert found is not None and satisfies(chosen, found)


def test_forbidden_exact_values_are_skipped() -> None:
    chosen: list[Literal] = [(Prefix("cmd"), True), (Equals("cmd"), False)]
    found = exact_witness(chosen)
    assert found is not None and satisfies(chosen, found) and len(found) == len("cmd") + 1


def test_the_witness_does_not_depend_on_the_order_of_literals() -> None:
    chosen: list[Literal] = [
        (Suffix(".exe"), True),
        (Contains("\\temp\\"), True),
        (Prefix("c:"), False),
    ]
    assert exact_witness(chosen) == exact_witness(list(reversed(chosen)))


def test_the_solver_applies_to_plain_patterns_only() -> None:
    assert applies([(Suffix(".exe"), True), (Equals("a"), False)])
    assert not applies([(Glob(("a", Wildcard.ANY, "b")), True)])
    many = [(Contains(str(index)), True) for index in range(MAX_REQUIRED + 1)]
    assert not applies(many)
