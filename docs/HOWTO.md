# skill-checker — как пользоваться

## TL;DR

Перед установкой любого third-party скилла → запускай `/skill-checker <путь>`. На выходе:
🔴 RED (выкидываем) / 🟡 YELLOW (готовые diff'ы для патчей) / 🟢 GREEN (команда установки).

---

## Когда использовать

**Всегда перед установкой постороннего скилла:**
- Скачал что-то из github / подсунул друг / нашёл в чате
- Любой скилл, который ты сам не написал

**Регулярно для уже установленных:**
- При обновлении (upstream поменялся → пере-проверить)
- Раз в месяц для тех, что давно лежат — на случай если автор «обновил» чужими руками

**Можно скипнуть для:**
- Скиллов, что ты пишешь сам с нуля (но плохого тоже не будет — поможет не забыть про valid baseline)
- Официальных Anthropic-скиллов в `/mnt/skills/public/`

---

## Базовый workflow (3 шага)

### Шаг 1 — Положи скилл в staging, не сразу в `~/.claude/skills/`

```bash
# Распакуй или склонируй скачанное в staging-папку:
mkdir -p ~/staging/skills && \
cd ~/staging/skills && \
git clone https://github.com/some-author/some-skill.git
# или
unzip ~/Downloads/some-skill.zip -d ~/staging/skills/
```

**Принцип:** скилл не ставится в активную позицию (`~/.claude/skills/`) до проверки. Если он окажется RED — просто `rm -rf` staging-папки.

### Шаг 2 — Запусти `/skill-checker`

В Claude Code в новой сессии:

```
/skill-checker ~/staging/skills/some-skill/
```

**Важно:** Claude **не может** автоматически дёрнуть этот скилл — у него `disable-model-invocation: true`. Только ты явно через `/`. Это by design — иначе чекер мог бы запуститься сам на свои же файлы и зациклиться.

Claude прочитает `SKILL.md` чекера, выполнит `scan.py` через bash, и выдаст вердикт.

### Шаг 3 — Действуй по вердикту

- 🟢 GREEN → команда установки в выводе → копируешь в `~/.claude/skills/` → новая сессия Claude Code → пользуешься
- 🟡 YELLOW → diff'ы → применяешь руками → re-run чекер → итерируешь до GREEN
- 🔴 RED → `rm -rf ~/staging/skills/some-skill` → не оборачиваться

---

## Что значат вердикты

### 🔴 RED — удаляем, не патчим

Чекер увидел признаки **умысла**, не торопыги:
- эксфильтрация данных (webhook.site, pastebin, ngrok)
- persistence (запись в `~/.bashrc`, git hooks, launchd)
- обфускация (`base64 -d | sh`, `eval(decoded)`)
- чтение `~/.ssh/`, `~/.aws/`, keychain без обоснования
- description-vs-behavior mismatch (заявлен summarizer, читает credentials)
- anti-user instructions ("do not tell the user", "run silently")
- policy override ("ignore safety", "developer mode")

**Что делать:** удалить и забыть. Не пытаться "патчить" — у malicious скиллов защита эшелонированная, заткнёшь одну дыру, другая откроется.

### 🟡 YELLOW — патчим по diff'ам

Чекер увидел торопыга-баги: автор плохо разбирается в безопасности, но не злодей:
- широкие `allowed-tools` (`Bash(python3 *)`, `Bash(rm *)`)
- `$0` вместо `$1`
- predictable `/tmp/` без mktemp
- нет валидации slug → path traversal
- нет защиты от prompt injection в untrusted data
- subprocess без timeout / shell=True / отсутствие symlink check
- конфликт с copyright ("copy snippet exactly")

Чекер выдаёт **готовые diff'ы**: "найди вот эту строку → замени на эту". Применяешь руками — он сам не правит файлы.

### 🟢 GREEN — ставим

Никаких CRITICAL findings, defensive practices на месте. Команда установки в выводе.

**Но:** GREEN не означает "100% безопасно". Это означает "статический скан не нашёл известных паттернов". Sophisticated targeted attack может пройти. Не запускай GREEN-скилл на чувствительных файлах в первый раз.

---

## Как работать с 🟡 YELLOW диффами

Каждый патч в выводе чекера выглядит так:

```markdown
### Patch 1: Wildcard в allowed-tools
**File:** SKILL.md
**Severity:** HIGH
**Why:** Bash(python3 *) lets the model run arbitrary Python (effectively RCE)

Replace:
allowed-tools: Bash(python3 *) Bash(...)

With:
allowed-tools: Bash(python3 ~/.claude/skills/some-skill/scripts/extract.py *) Bash(...)
```

**Алгоритм:**
1. Открой указанный файл
2. Найди строку из "Replace"
3. Замени на "With"
4. Re-run `/skill-checker <path>`
5. Если ещё YELLOW — повторяй для следующего патча
6. Когда станет GREEN — ставь

**Если diff не подходит к твоей ситуации:** пропусти этот патч и опиши Claude в чате почему. Он подскажет альтернативу. Чекер выдаёт типовые шаблоны, под edge cases надо думать руками.

---

## Tips & Best Practices

**1. Staging directory pattern.**  
Никогда не скачивай прямо в `~/.claude/skills/`. Всегда staging → check → install.

**2. Re-audit при апдейтах.**  
Если автор скилла выкатил v2, не сливай слепо. Делай так:
```bash
cd ~/.claude/skills/some-skill && git pull && cd -
/skill-checker ~/.claude/skills/some-skill/
```
Свежий скилл может ввести новые паттерны. Чекер увидит.

**3. Параноидально перед запуском.**  
Даже после GREEN, в первый раз запускай скилл на безобидных тестовых данных. Создай fake input, посмотри что происходит. Не давай ему сразу production файлы.

**4. Чтение вердикта целиком.**  
Чекер выдаёт **все** findings, даже LOW. Прочти LOW тоже — это часто quality issues, которые в скилле, который ты собираешься использовать каждый день, лучше тоже подправить.

**5. Если всё подозрительно.**  
Если у тебя плохое ощущение от скилла даже после GREEN — слушай интуицию. Чекер закрывает 95% классов угроз, но не все. Если автор выглядит сомнительно, репозиторий свежий, документация туманная — лучше не ставить.

---

## Troubleshooting

**"`/skill-checker` не подтягивается, Claude не понимает команду"**  
→ Перезапусти Claude Code сессию (новый чат, не F5). Скиллы кешируются на старте.

**"Claude в чате не запускает scan.py автоматически"**  
→ Это нормально. У чекера `disable-model-invocation: true`. Скажи модели явно: *"запусти `python3 ~/.claude/skills/skill-checker/scripts/scan.py <путь>` и пройди по SKILL.md чекеру"*. После этого она пройдётся по чеклисту руками.

**"Чекер выдал кучу CRITICAL на security-документ-скилле"**  
→ См. секцию Limitations в SKILL.md чекера. Скиллы, которые **документируют** атаки (как сам skill-checker), имеют known false positives — `references/red-flags.md` буквально перечисляет опасные паттерны как примеры. Это не настоящие угрозы.

**"Чекер выдал YELLOW, но я не понимаю как применить diff"**  
→ Скопируй вывод чекера в новый чат с Claude и попроси: *"объясни этот diff и помоги применить к файлу X"*. Он расшифрует и предложит конкретные строки.

**"Я всё запатчил, но чекер всё равно YELLOW"**  
→ Возможно, ты что-то пропустил, или новые правила сработали после изменений. Прочти все findings заново — может, появилась новая категория. Если совсем тупик — кидай вывод чекера в чат, разберёмся.

**"`scan.py` выдаёт `BOOK_SKILL_WORKDIR env var is required`"**  
→ Это сообщение от **другого** скрипта (extract.py из book-to-skill, не scan.py). Перепутаны пути. Проверь что вызываешь именно `~/.claude/skills/skill-checker/scripts/scan.py`.

**"Хочу проверить только `scan.py` без `/skill-checker`"**  
→ Можно напрямую:
```bash
python3 ~/.claude/skills/skill-checker/scripts/scan.py ~/staging/skills/some-skill/ | jq .
```
Получишь сырой JSON с findings. Без LLM-уровневых проверок (Step 5-7), но static-pass пройдёт.

---

## Известные ограничения

Чекер не панацея. Что он **не закроет**:
- **Runtime fetches.** Скилл, который при запуске скачивает malicious код с контролируемого автором сервера, статический скан не увидит. Защита: 🔴 любой скилл с network calls + writeable filesystem operations.
- **Supply chain.** Если скилл импортирует библиотеку с CVE или с малициозным апдейтом — это не зона ответственности чекера. Держи зависимости pinned и проверяй отдельно.
- **Sophisticated bypass.** Adversarial код может маскироваться под benign. Когда видишь 5+ HIGH findings, даже если каждый объясним — это паттерн, не оправдывайся.
- **Update means re-audit.** GREEN сегодня ≠ GREEN завтра. После любого upstream-апдейта пере-проверяй.

---

## Финальный совет

**Не доверяй автоматизации полностью.** Чекер — фильтр, не присяжный. Он отсекает 95% мусора, но финальное решение — за тобой. После GREEN глянь сам на `SKILL.md` скилла глазами 30 секунд. Если что-то странно — стоп и в чат.

Хороший workflow:
1. Скилл интересный, увидел в чате/гитхабе
2. → staging
3. → `/skill-checker`
4. → если 🟢 — глянуть `SKILL.md` глазами на 30 сек
5. → если ничего не смущает — ставить
6. → первый запуск на безобидном тестовом входе
7. → если всё ок — пустить в боевую работу
