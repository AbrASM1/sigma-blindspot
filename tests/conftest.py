import os
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import settings

settings.register_profile("dev", deadline=None)
settings.register_profile("ci", derandomize=True, deadline=None, print_blob=True)
settings.register_profile("intensive", max_examples=10_000, deadline=None, print_blob=True)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci" if os.environ.get("CI") else "dev"))

type Writer = Callable[[str, str | bytes], Path]

DOC_SAMPLE = """\
<Sysmon schemaversion="4.82">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <ProcessTerminate onmatch="include" />
    <NetworkConnect onmatch="include">
      <DestinationPort>443</DestinationPort>
      <DestinationPort>80</DestinationPort>
    </NetworkConnect>
    <NetworkConnect onmatch="exclude">
      <Image condition="end with">iexplore.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
"""

DOC_RULE_GROUPS = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="group 1" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image name="create" condition="contains">timeout.exe</Image>
        <CommandLine condition="contains">100</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup groupRelation="or">
      <ProcessTerminate onmatch="include">
        <Image name="terminate" condition="contains">timeout.exe</Image>
        <Image condition="contains">ping.exe</Image>
      </ProcessTerminate>
    </RuleGroup>
    <ImageLoad onmatch="include"/>
  </EventFiltering>
</Sysmon>
"""


def line_of(text: str, needle: str) -> int:
    numbers = [number for number, line in enumerate(text.split("\n"), start=1) if needle in line]
    if len(numbers) != 1:
        raise LookupError(f"{needle!r} is on {len(numbers)} lines, expected exactly one")
    return numbers[0]


@pytest.fixture
def write(tmp_path: Path) -> Writer:
    def write_file(name: str, content: str | bytes) -> Path:
        path = tmp_path / name
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    return write_file
