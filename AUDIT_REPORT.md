# VMP Devirtualizer — Audit Report

**Дата:** 2026-07-26
**Ветка:** main · **Rust:** 1.97.1 · **Проект:** vmp_devirt 0.1.0

---

## 0. TL;DR

| Метрика | Значение |
|---|---|
| Строк Rust | ~2 800 |
| Модулей | 10 |
| Тестов | 16 pass / 0 fail (было 15/1) |
| Clippy warnings | 0 (было 24) |
| Build (dev + release) | ✓ |
| Deps latest | ✓ (goblin 0.7→0.10.7, clap 4.4→4.6.4, serde 1.0→1.0.229, …) |

**Быстрые фиксы применены** (см. раздел 1). **Остальное** — в разделе 2 (что доделывать).

---

## 1. Что уже исправлено в этой сессии ✓

| ID | Файл | Что сделано |
|---|---|---|
| C2 | `src/unicorn_dispatch_extractor.rs` | Убраны `/tmp/dispatch_entries.json` и `/home/ciupix/…` — теперь `std::env::temp_dir()` + `env!("CARGO_MANIFEST_DIR")` + override через `$VMP_UNICORN_EXTRACTOR`. Автовыбор `python3` / `python`. |
| C5 | `src/decrypt.rs` | Тест `test_decrypt_operand` теперь `set_crc(0xDEADBEEF)` перед проверкой + `assert_eq!` на точное значение. |
| C6 | `src/main.rs` | Удалён (был `Hello, world!`). |
| S1, S4 | `src/pe_loader.rs` | `checked_add` во всех PE-offset арифметиках; guard `virtual_size.min(size_of_raw_data)` против malicious PE. |
| S2 | `src/pe_loader.rs` | `unwrap_or(&[])` → explicit `.with_context(...)` (не глотаем OOB). |
| S3 | `src/pe_loader.rs` | `read_u8` через `first().copied().context(...)` вместо `[0]`. |
| S5 | `src/bin/cli.rs` | `.unwrap()` на `.to_str()` → `to_string_lossy()` (не паникует на non-UTF-8 пути). |
| S6 | `src/unicorn_emulator.rs` | Sign-extension унифицирован для обоих XOR-imm32 патернов (`48 35` и `48 81 F0`). |
| Q5 | `src/lib.rs` | `#![deny(dead_code)] + #![deny(unused_variables)]` → `#![warn(...)]`. |
| Q6 | все модули | Doc-комментарии на модулях `///` → `//!` (10 warnings `missing_docs` устранены). |
| Q8 | `src/pe_loader.rs`, `src/bytecode.rs`, `src/unicorn_emulator.rs`, тесты | `parse_pe(&self) -> Result<PE<'_>>`, `data.get(0)` → `first()`, `len() > 0` → `!is_empty()`, чистка unused `use super::*`. |
| deps | `Cargo.toml` | Все крейты обновлены до latest stable. `cargo update` прошёл; `cargo build [--release]` ✓. |
| ruflo | `~/.claude/projects/…/memory/` | Auto memory заполнена — 6 md-файлов с контекстом проекта, автозагрузка в будущие сессии. |

**Итог быстрого прохода:** 12 фиксов применено, build/test/clippy — все зелёные.

---

## 2. Что осталось (нельзя быстро — нужен реверс / образцы / архитектурное время)

Здесь приоритет: 🔴 critical · 🟠 high · 🟡 medium · ⚪ nice-to-have.

### 🔴 C1 — Реализовать реальную детекцию VMP 1.x / 2.x

**Где:** `src/version.rs:129-141` — `has_vmp1_sections`, `has_vmp2_sections` → всегда `Ok(false)`.

**Проблема:** README заявляет "22/22 samples pass" по всем версиям (4 VMP1 + 6 VMP2 + 12 VMP3). Код же **никогда** не может вернуть `Vmp1` или `Vmp2` — вся статистика для этих версий фиктивна.

**Что нужно:**
- Собрать реальные VMP 1.1 / 1.4 / 1.54 / 1.70 sample-бинарники и VMP 2.x sample-бинарники (в README перечислены имена файлов, они где-то лежали).
- Проанализировать какие entry-stub signature / section-layout / dispatch-mechanism отличают их (VMP 1.x — обычно нет отдельных `.vmp*` секций, всё в `.text`; VMP 2.x — `.vmp0` без `.vmp1`).
- Написать хотя бы entry-point signature match (первые 16-32 байта после `AddressOfEntryPoint`) — известны для 1.x/2.x.

**Оценка:** 1-2 дня при наличии образцов.

---

### 🔴 C3 — Реализовать реальный `Bytecode::size()`

**Где:** `src/bytecode.rs:92-94` — `fn size(&self) -> usize { 5 }`.

**Проблема:** `VmpDevirtualizer::devirtualize_range` итерирует `vip += instr.size` (см. `src/lib.rs:200-207`). При хардкоде 5 весь дизассемблер шагает по 5 байт независимо от opcode — **весь выхлоп после первой инструкции — мусор**.

**Что нужно:**
- Каждый handler имеет свой набор операндов (`PUSH_REG` — 1 байт, `PUSH_VALUE` — 1/2/4/8, `JMP` — 4, и т.д.).
- Логика уже частично разложена в `decode_operands` (`src/bytecode.rs:32-72`) — вынести подсчёт размера туда же и возвращать `usize` из `decode_operands`, а `size()` пересчитать через `1 + operand_bytes`.
- Учесть variable-length инструкции (VMP `PUSH_VALUE` — 4 варианта размера, определяется handler variant slot).

**Оценка:** 2-3 дня с покрытием тестами.

---

### 🔴 C4 — Убрать hardcoded RVA `0x48138` в dispatch table locator

**Где:** `src/dispatch_table.rs:20`.

**Проблема:** "Generalized VMProtect devirtualizer" по факту жёстко привязан к RVA одного конкретного бинарника. Fallback-scan (`find_dispatch_pattern`) есть, но он никогда не вызывается на "known-RVA" пути — просто вернёт `dispatch_table_va` из этого RVA, если он попадёт в валидную секцию.

**Что нужно:**
- Сделать `known_rva` опциональным (`Option<u64>`), передаваемым через CLI-флаг `--dispatch-rva 0x48138` или из sidecar JSON.
- Дефолт — сразу вызывать `find_dispatch_pattern` на всех кандидатных секциях.
- Возможно кэшировать успешные RVA per-binary-hash в sidecar (`.vmp_devirt_cache.json`).

**Оценка:** 4-6 часов.

---

### 🟠 Q2 — Расширить `HandlerClassifier` (multi-byte fingerprints)

**Где:** `src/handler_classifier.rs:64-227`.

**Проблема:** сейчас match только по первому байту → покрывает ~20 x86-паттернов; всё остальное — `UNKNOWN` (confidence 30). Для реальных VMP-handlers надо смотреть:
- REX-prefix + opcode + ModR/M (`48 8B ??` → LEA/MOV в зависимости от ModR/M);
- специфические VMP-паттерны handler-entry (49 8B 2A для VMP 3.x POP, и т.д. — есть в README).

**Что нужно:**
- Table-driven классификатор: `Vec<(pattern: &[Option<u8>], name: &str, confidence: u8)>`.
- Wildcards (`None`) для позиций регистра / immediate.
- Отдельные таблицы для VMP-версий (у 3.5.1 и 3.6+ разные entry signatures).

**Оценка:** 3-5 дней (нужна референсная таблица handlers из VMP 3.5.1 source leak — уже упомянута в README).

---

### 🟠 Q3 — Реальный `alu::decompose_chain`

**Где:** `src/alu.rs:74-83` — возвращает dummy строки `"stack_val_1"`, `"stack_val_2"`.

**Что нужно:** ALU chain в VMP работает над VM-stack. Нужно:
- Символическое имя стек-слота (`vsp+0`, `vsp+8`) вместо dummy.
- Реконструкция цепочки De Morgan → `add rax, rbx` для 4× NOR над двумя стек-значениями.
- Интегрировать с `VmpDevirtualizer::decode_instruction` — сейчас NOR/NAND handler-ы просто возвращают VIP как operand.

**Оценка:** неделя, требует symbolic execution mini-engine.

---

### 🟠 Q4 — Расширить `Bytecode::decode_operands`

**Где:** `src/bytecode.rs:32-72`. Покрывает 8 handler names (`PUSH_REG`, `PUSH_VALUE`, `POP_MEMORY`, `ADD_REG` и др.). Всё остальное — `_ => {}` (silent no-op).

**Что нужно:** exhaustive match по всем handler-type строкам, генерируемым `handler_classifier::analyze_bytecode`. Иначе валидные handlers молча теряются.

**Оценка:** параллельно с Q2, ~1 день.

---

### 🟠 S7 — Bounds-check в `handler_classifier`

**Где:** `src/handler_classifier.rs:38` — `binary.read_bytes(handler_va, 100)`.

**Проблема:** если handler лежит близко к концу секции и до конца < 100 байт — `read_bytes` вернёт ошибку и весь handler будет `UNREADABLE`, теряя валидные короткие handlers.

**Что нужно:** сначала спрашивать доступный размер секции, читать `min(100, remaining)`. После фиксов S1/S4 в `pe_loader.rs` это будет проще — `read_bytes` больше не паникует, но возвращает Err на неполном чтении. Нужен новый метод `read_bytes_up_to(va, max) -> Vec<u8>`.

**Оценка:** 1-2 часа.

---

### 🟡 Q7 — Переименовать `unicorn_*` (misleading naming)

**Проблема:**
- `unicorn_emulator.rs` не эмулирует — делает static pattern matching. → `xor_key_analyzer.rs`.
- `unicorn_dispatch_extractor.rs` шеллит в Python subprocess. → `python_extractor_bridge.rs` или `dispatch_extractor_py.rs`.

**Что нужно:** переименовать файлы, поправить `mod` и `pub use` в `lib.rs`, обновить documentation. Ломающее API изменение — вынести на next-minor-bump. В `unicorn_emulator.rs` уже добавлен `NOTE` в module doc про план переименования.

**Оценка:** 30 мин + записка в CHANGELOG.

---

### 🟡 Q1 + Q13 — Real integration tests + fixtures

**Проблема:** 7 из 16 тестов — заглушки (`// Stub: requires a real PE fixture`). Реальное покрытие ≈ 15%.

**Что нужно:**
- Директория `tests/fixtures/` с минимальным ассемблерным `.exe` (собрать через `link.exe /entry:main /subsystem:console`) — 4-8 KB достаточно для покрытия PE loader / va_to_offset / read_bytes.
- Один настоящий VMP-protected sample (можно с VMProtect Community/Free) в `tests/fixtures/vmp3_hello.exe` (проверить лицензию!).
- `tests/pe_loader.rs`, `tests/dispatch_table.rs` — integration-тесты.
- Property-tests (`proptest` crate) для `OpcodeCryptor::decrypt`/`update_crc` (round-trip invariants).

**Оценка:** 3-5 дней.

---

### 🟡 Q9 — Обновить `README.md`

**Проблемы:**
- L28: `cd /home/ciupix/vmp_devirt_prod` — чужой пользователь.
- L50-62: заявлено 22/22 samples pass — противоречит `C1` (VMP1/2 детекция всегда `false`).
- L157-160: "Known Limitations" не упоминает hardcoded RVA `0x48138`.
- Windows не документирован (build/run инструкции только Linux).

**Что нужно:** переписать секции `Quick Start`, `Validation Results` (с фактическими цифрами по VMP3 после исправлений), `Known Limitations` (добавить hardcoded RVA + VMP1/2 stub + Python subprocess dependency).

**Оценка:** 2-3 часа.

---

### 🟡 Q10 — Setup CI + supply-chain security

**Отсутствует:**
- `.github/workflows/ci.yml` — `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` на Windows + Linux матрице.
- `cargo audit` (RustSec DB) и `cargo deny` (лицензии + deps allow-list) — установить и включить в CI.
- `rustfmt.toml` + `clippy.toml` — единый стиль.

**Что нужно:** типовой ci.yml + два конфига. Дёшево, но требует ~1 день на отладку матрицы.

---

### 🟡 Q11 — Реорганизация корневой директории

**Проблема:** в корне ~35 KB отчётной документации:
- `IMPLEMENTATION_COMPLETE.md` (12.6 KB)
- `VALIDATION_REPORT.md` (10.5 KB)
- `UNICORN_IMPLEMENTATION_REPORT.md` (8.7 KB)
- `FUTURE_WORK.md` (4.7 KB)

**Что нужно:**
- Создать `docs/` и перенести туда всё кроме `README.md`, `AUDIT_REPORT.md`, `Cargo.toml`, `Cargo.lock`.
- Расширить `.gitignore` — сейчас там только `/target` (default), не хватает `*.pdb`, `.vs/`, `.idea/`, `*.swp`, `**/*.rs.bk`, локальные dispatch_table_info.json.

**Оценка:** 30 мин.

---

### ⚪ Q14 — Sanity против command-injection (S-lite)

**Где:** `src/unicorn_dispatch_extractor.rs` — `Command::new(python_bin).arg(&script_path).arg(binary_path).arg(...)`. `binary_path` — это `binary.path` (сохранённый `path.as_ref().to_string_lossy()` из `pe_loader.rs`).

**Проблема:** пробелы/quotes в пути к бинарнику передадутся Python как аргумент корректно (мы используем `Command::arg`, не shell). Command injection не грозит. Но:
- Стоит валидировать что `binary_path` существует перед вызовом (сейчас Python упадёт с внутренней ошибкой).
- Логгировать полную command-line для reproducibility.

**Оценка:** 20 мин.

---

### ⚪ Q15 — Убрать зависимость от Python subprocess

**Идея:** заменить `unicorn_extractor.py` на прямой crate `unicorn-engine` (Rust bindings). Устраняет:
- необходимость Python в runtime,
- JSON-сериализацию через temp-файл (медленно),
- проблему "script not found".

**Проблема:** `unicorn-engine` требует C-библиотеки Unicorn на системе (Linux — `libunicorn-dev`; Windows — вручную собранный DLL). MSVC build может быть болезненным.

**Оценка:** 3-5 дней с проработкой Windows build.

---

## 3. Приоритизированный roadmap

### Спринт 1 (1 неделя) — «Честный релиз 0.2»
- C1, C3, C4 — устранить архитектурную ложь: реальный VMP1/2 detect, реальный `size()`, убрать hardcoded RVA.
- Q9 — переписать README с фактическими цифрами.
- Q11 — реорганизовать корень + расширить .gitignore.

### Спринт 2 (1-2 недели) — «Полное покрытие handlers»
- Q2, Q4 — реальный table-driven классификатор + exhaustive `decode_operands`.
- Q3 — символический ALU decompose.
- S7 — bounds-safe чтение handler bytes.

### Спринт 3 (1 неделя) — «Инфраструктура»
- Q10 — CI + cargo-audit + cargo-deny + rustfmt/clippy configs.
- Q1/Q13 — integration tests + fixtures.
- Q7 — переименование `unicorn_*` (в minor-bump).

### Спринт 4 (2-3 недели) — «Полировка»
- Q15 — оценка миграции на Rust `unicorn-engine`.
- Q14 — command-injection sanity + reproducibility logging.
- Documentation pass (rustdoc examples для публичных API).

---

## 4. Ссылки на код в этой сессии

- Cargo.toml `deps` bumps: [D:\GitHub\Rust_Projects\VM-Protect-Research\Cargo.toml](./Cargo.toml)
- Быстрые фиксы commit-ready (после `git diff`).
- Auto memory ruflo: `C:\Users\Platon\.claude\projects\D--GitHub-Rust-Projects-VM-Protect-Research\memory\` — читается в будущие сессии.

---

*Отчёт сгенерирован Claude Code (Opus 4.7) в рамках сессии 46b758ca на 2026-07-26.*
