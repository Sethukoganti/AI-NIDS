import pathlib
p = pathlib.Path("backend/tests/test_admin_config.py")
t = p.read_text(encoding="utf-8")

t = t.replace(
  '    # Every configured section must map onto one of the console sections.\n'
  '    sections = {s["name"] for s in body["sections"]}\n'
  '    assert sections.issubset(set(expected) | set(body["section_aliases"].values()))',
  '    # Every configured section must fold onto one of the eleven console sections.\n'
  '    aliases = body["section_aliases"]\n'
  '    sections = {s["name"] for s in body["sections"]}\n'
  '    for name in sections:\n'
  '        assert name in expected or aliases.get(name) in expected, (\n'
  '            f"section {name!r} maps to no admin console section"\n'
  '        )',
)
t = t.replace(
  '    assert body["status"] == "maintenance"\n'
  '    assert body["source"] in {"manual", "automatic", "system"}\n'
  '    assert body["reason"] == "planned window"\n'
  '    assert body["changed_at"]',
  '    assert body["status"] == "maintenance"\n'
  '    assert body["status_key"] == "maintenance"\n'
  '    assert body["source"] in {"manual", "automatic", "system"}\n'
  '    assert body["reason"] == "planned window"\n'
  '    assert body["label"]\n'
  '    assert body["configuration_applied"], "a status change must report what it applied"',
)
t = t.replace(
  '    assert body.get("effective_configuration"), "the status view must report what is live"\n'
  '    assert body.get("mode_label")',
  '    assert body.get("configuration_applied"), "the status view must report what is live"\n'
  '    assert body.get("label") and body.get("tone")\n'
  '    assert body["evaluable"] in (True, False)',
)
p.write_text(t, encoding="utf-8")
print("aligned")
