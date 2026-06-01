---
name: ru-notes
description: >-
  Двуязычный заметки-хелпер. Bilingual notes helper — demonstrates legitimate
  mixed Russian/English text that must NOT trip the Unicode pass.
when_to_use: >-
  Триггеры — "сделай заметку", "make a note", "tidy notes"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *) Bash(echo *)
argument-hint: <path>
arguments: [path]
---

# RU Notes

Двуязычный скилл-пример. Содержит легитимный русский текст, дефисные
RU/EN-композиты и эмодзи — ничего из этого не должно срабатывать в Unicode-пассе.

## Заметки

- Обычная русская проза: конфиги, токены, безопасность, аудит.
- Дефисные композиты: MCP-конфиг, AST-пасс, RTL-override, JSON-данные.
- Жаргон со склейкой: заinjectить, заmockать (Cyrillic glued to a Latin root —
  not a homoglyph, the Cyrillic letters cluster together).
- Эмодзи вердиктов: 🔴 🟡 🟢.
- Plain ASCII English line mentioning sudo and eval as ordinary words.

## Why this passes audit (negative test for the Unicode pass)

There are no invisible characters, no bidi controls, and no Tags-block
characters. The only mixed-script words are hyphenated compounds (which split on
the hyphen) and glued jargon (where the confusable Cyrillic letters sit next to
*other* Cyrillic letters, not inside a Latin word). The homoglyph rule fires only
on a Cyrillic/Greek look-alike embedded **inside** a Latin word, which appears
nowhere here.

Expected verdict: 🟢 GREEN, exit 0.
