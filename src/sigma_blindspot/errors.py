class SourceError(Exception):
    def __init__(self, message: str, line: int | None, source: str) -> None:
        super().__init__(message, line, source)
        self.message = message
        self.line = line
        self.source = source

    def __str__(self) -> str:
        location = self.source if self.line is None else f"{self.source}:{self.line}"
        return f"{location}: {self.message}"


class ConfigError(SourceError):
    pass


class EventError(SourceError):
    pass
