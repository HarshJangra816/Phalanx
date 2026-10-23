"""tree-sitter-php parsing + function-level slicing (ARCHITECTURE.md §3.1).

The LLM receives a ~50-150 line slice — never a whole file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Parser

PHP_LANGUAGE = Language(tree_sitter_php.language_php())

_FUNCTION_NODE_TYPES = {"function_definition", "method_declaration"}

DEFAULT_MAX_LINES = 150
DEFAULT_CONTEXT_LINES = 25


def _make_parser() -> Parser:
    try:
        return Parser(PHP_LANGUAGE)
    except TypeError:  # older tree-sitter API
        parser = Parser()
        parser.set_language(PHP_LANGUAGE)
        return parser


@dataclass
class FunctionSpan:
    name: str
    start_line: int  # 1-based, inclusive
    end_line: int    # 1-based, inclusive
    kind: str        # "function" | "method"


@dataclass
class CodeSlice:
    file: str
    name: str
    kind: str             # "function" | "window"
    start_line: int       # 1-based, inclusive
    end_line: int         # 1-based, inclusive
    text: str             # raw source of the slice
    total_lines: int      # lines in the whole file

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1

    def numbered(self) -> str:
        lines = self.text.splitlines()
        width = max(4, len(str(self.end_line)))
        return "\n".join(
            f"{self.start_line + i:>{width}}| {ln}" for i, ln in enumerate(lines)
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file, "name": self.name, "kind": self.kind,
            "start_line": self.start_line, "end_line": self.end_line,
            "line_count": self.line_count, "total_lines": self.total_lines,
        }


def _parse(path: Path, source: bytes):
    parser = _make_parser()
    return parser.parse(source)


def parse_functions(path: str | Path) -> list[FunctionSpan]:
    """Return every top-level function/method with 1-based line spans."""
    p = Path(path)
    source = p.read_bytes()
    tree = _parse(p, source)

    spans: list[FunctionSpan] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in _FUNCTION_NODE_TYPES:
            name_node = node.child_by_field_name("name")
            name = source[name_node.start_byte:name_node.end_byte].decode(
                "utf-8", errors="replace") if name_node else "<anonymous>"
            spans.append(FunctionSpan(
                name=name,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                kind="method" if node.type == "method_declaration" else "function",
            ))
        else:
            stack.extend(node.children)
    spans.sort(key=lambda s: s.start_line)
    return spans


def _enclosing(spans: list[FunctionSpan], line: int) -> FunctionSpan | None:
    for span in spans:
        if span.start_line <= line <= span.end_line:
            return span
    return None


def _window(total: int, start_line: int, end_line: int,
            context: int, max_lines: int) -> tuple[int, int]:
    lo = max(1, start_line - context)
    hi = min(total, end_line + context)
    if hi - lo + 1 > max_lines:
        # shrink around the center of the target range
        center = (start_line + end_line) // 2
        lo = max(1, center - max_lines // 2)
        hi = min(total, lo + max_lines - 1)
        lo = max(1, hi - max_lines + 1)
    return lo, hi


def slice_for_lines(path: str | Path, start_line: int, end_line: int,
                    max_lines: int = DEFAULT_MAX_LINES,
                    context: int = DEFAULT_CONTEXT_LINES) -> CodeSlice:
    """Slice covering [start_line, end_line]: enclosing function when small
    enough, otherwise a bounded window. Never exceeds max_lines."""
    p = Path(path)
    text_all = p.read_text(encoding="utf-8", errors="replace")
    lines = text_all.splitlines()
    total = len(lines)

    start_line = max(1, min(start_line, total))
    end_line = max(start_line, min(end_line, total))

    fn = _enclosing(parse_functions(p), start_line)
    if fn is not None:
        span_start, span_end = fn.start_line, fn.end_line
        if span_end - span_start + 1 <= max_lines:
            # widen if the target range pokes outside (rare)
            span_start = min(span_start, start_line)
            span_end = max(span_end, end_line)
            text = "\n".join(lines[span_start - 1:span_end])
            return CodeSlice(file=str(p), name=fn.name, kind="function",
                             start_line=span_start, end_line=span_end,
                             text=text, total_lines=total)
        # oversized function: window inside it, clipped to the function
        lo, hi = _window(span_end - span_start + 1, start_line - span_start + 1,
                         end_line - span_start + 1, context, max_lines)
        lo += span_start - 1
        hi += span_start - 1
        lo = max(lo, span_start)
        hi = min(hi, span_end)
        text = "\n".join(lines[lo - 1:hi])
        return CodeSlice(file=str(p), name=fn.name, kind="function",
                         start_line=lo, end_line=hi, text=text, total_lines=total)

    lo, hi = _window(total, start_line, end_line, context, max_lines)
    text = "\n".join(lines[lo - 1:hi])
    return CodeSlice(file=str(p), name="<toplevel>", kind="window",
                     start_line=lo, end_line=hi, text=text, total_lines=total)
