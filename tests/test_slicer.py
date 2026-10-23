from pathlib import Path

import pytest

from phalanx.scanner.slicer import parse_functions, slice_for_lines

LAB = Path(__file__).resolve().parents[1] / "lab" / "public" / "index.php"


def test_parse_functions_finds_all_lab_functions():
    spans = parse_functions(LAB)
    names = [s.name for s in spans]
    assert names == ["get_user", "greet", "ping_host", "save_upload", "load_page"]
    ping = next(s for s in spans if s.name == "ping_host")
    assert ping.start_line == 17 and ping.end_line == 20
    assert all(s.kind == "function" for s in spans)


def test_slice_returns_enclosing_function():
    sl = slice_for_lines(LAB, 19, 20)
    assert sl.kind == "function"
    assert sl.name == "ping_host"
    assert sl.start_line == 17 and sl.end_line == 20
    assert '$_GET[\'host\']' in sl.text


def test_slice_numbering_uses_absolute_lines():
    sl = slice_for_lines(LAB, 19, 19)
    numbered = sl.numbered().splitlines()
    assert numbered[0].lstrip().startswith("17|")
    assert any("system(" in ln for ln in numbered)


def test_slice_outside_functions_yields_window(tmp_path):
    f = tmp_path / "top.php"
    f.write_text("<?php\n$a = 1;\n" + "\n".join(
        f"$v{i} = {i};" for i in range(100)) + "\n", encoding="utf-8")
    sl = slice_for_lines(f, 60, 61)
    assert sl.kind == "window"
    assert sl.start_line <= 60 and sl.end_line >= 61
    assert sl.line_count <= 150


def test_oversized_function_is_capped(tmp_path):
    f = tmp_path / "big.php"
    body = "\n".join(f"    $x{i} = {i};" for i in range(400))
    f.write_text(f"<?php\nfunction big() {{\n{body}\n}}\n", encoding="utf-8")
    spans = parse_functions(f)
    assert spans and spans[0].end_line > 400
    sl = slice_for_lines(f, 200, 201)
    assert sl.line_count <= 150
    assert sl.start_line <= 200 <= sl.end_line


def test_slice_line_count_never_exceeds_max(tmp_path):
    f = tmp_path / "all.php"
    f.write_text("<?php\n" + "\n".join(f"echo {i};" for i in range(300)),
                 encoding="utf-8")
    sl = slice_for_lines(f, 1, 300, max_lines=100)
    assert sl.line_count <= 100


def test_methods_are_detected(tmp_path):
    f = tmp_path / "cls.php"
    f.write_text(
        "<?php\nclass Repo {\n    public function find($id) {\n"
        "        return $id;\n    }\n}\n", encoding="utf-8")
    spans = parse_functions(f)
    assert len(spans) == 1
    assert spans[0].name == "find"
    assert spans[0].kind == "method"


@pytest.mark.parametrize("line", [6, 8, 13, 25, 30])
def test_every_vuln_line_has_a_slice(line):
    sl = slice_for_lines(LAB, line, line)
    assert sl.start_line <= line <= sl.end_line
    assert sl.text
