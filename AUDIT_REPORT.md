# VMP Devirtualizer — Audit Report

**Дата:** 2026-07-26
**Ветка:** main · **Rust:** 1.97.1 · **Проект:** vmp_devirt 0.1.0

---

## 0. TL;DR

| Метрика | Значение |
|---|---|
| Строк Rust | ~2 800 |
| Модулей | 12 |
| Тестов | 66 pass / 0 fail (было 16/0) |
| Clippy warnings | 0 (`cargo clippy --all-targets`) |
| Build (dev + release) | ✓ |
| CI | ✓ `.github/workflows/ci.yml` — Windows + Linux матрица (build/test/clippy/fmt) + отдельный `security-audit` job (`cargo audit` + `cargo deny check`) |
| Deps latest | ✓ (goblin 0.10.7, clap 4.6.4, serde 1.0.229, serde_json 1.0.151, anyhow 1.0.104, log 0.4.33, env_logger 0.11.11) |

**Быстрые фиксы применены** (см. раздел 1). Начиная с этой сессии раздел 1 также включает архитектурные фиксы C1/C3/C4/X1 и инфраструктурные Q6/Q7/Q10/Q11, ранее числившиеся в разделе 2 — они landed в коммитах `cbb6186` (audit-driven overhaul: real detectors, dual-bitness, hardening) и `d81cfbd` (CI + supply-chain security) на `main`. **Остальное** — в разделе 2 (что доделывать).

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

## 1a. Что доделано в архитектурном проходе (`cbb6186`, `d81cfbd`) ✓

| ID | Файл | Что сделано |
|---|---|---|
| C1 | `src/version.rs`, `src/version_matchers.rs` (новый) | `has_vmp1_sections`/`has_vmp2_sections`-заглушки заменены на скоринговый эвристический каскад: entry-stub байт-паттерны (pushad+mov esi,imm32 для 1.x; push+call/jmp для 2.x/3.x), layout `.vmp0`/`.vmp1`, RWX-характеристики entry-секции, строковый маркер `"VMProtect"`. `VersionDetector::detect` теперь возвращает `(VmpVersion, u8 confidence)` вместо просто `VmpVersion`. |
| C3 | `src/bytecode.rs` | `size(&self) -> usize` (хардкод `5`) заменён на `size(&self, handler: &Handler) -> Result<usize>`, вычисляемый из реального operand-layout хендлера (`operand_bytes`). `devirtualize_range` в `lib.rs` теперь шагает по реальному размеру инструкции. |
| C4 | `src/dispatch_table.rs` | Хардкод RVA `0x48138` убран. `DispatchTableLocator::locate(binary, hint_rva: Option<u64>)` — хинт валидируется тем же порогом (200/256 валидных указателей), что и fallback pattern-scan; при провале хинта или его отсутствии сразу идёт скан секций. CLI-флаг `--dispatch-rva <RVA>` добавлен в `src/bin/cli.rs`. |
| X1 | `src/pe_loader.rs`, `src/xor_key_analyzer.rs`, `src/handler_classifier.rs` | Новый `enum Bitness { X86, X64 }`, определяется из `pe.is_64`. Прокинут в `XorKeyAnalyzer` (entry_size 4 vs 8, XOR-паттерны с/без REX) и `HandlerClassifier` (ветка REX-префикса `0x48` теперь gated на `Bitness::X64`; на x86 `0x48` — это `DEC EAX`, раньше классифицировался неверно). Проверено юнит-тестами на обоих bitness, live x86 VMP-сэмпл не прогонялся. |
| S7 | `src/pe_loader.rs`, `src/handler_classifier.rs` | Новый `PEBinary::read_bytes_up_to(va, max) -> Result<Vec<u8>>` — читает `min(max, remaining-in-section)` вместо жёстких 100 байт. `HandlerClassifier::classify` использует его, короткие handlers у границы секции больше не помечаются `UNREADABLE`. |
| Q7 | `src/unicorn_emulator.rs` → `src/xor_key_analyzer.rs`, `src/unicorn_dispatch_extractor.rs` → `src/dispatch_extractor_py.rs` | Файлы и типы переименованы: `UnicornEmulator` → `XorKeyAnalyzer`, `UnicornDispatchExtractor` → `DispatchExtractorPy`. `mod`/`pub use` в `lib.rs` и README обновлены. |
| Q10 | `.github/workflows/ci.yml`, `rustfmt.toml`, `clippy.toml` | CI добавлен: build/test/clippy/fmt на Windows + Linux матрице, отдельный `security-audit` job (`cargo audit` + `cargo deny check`). `rustfmt.toml`/`clippy.toml` закоммичены, `cargo fmt --all` применён по всему проекту. |
| Q11 | `docs/` | `IMPLEMENTATION_COMPLETE.md`, `VALIDATION_REPORT.md`, `UNICORN_IMPLEMENTATION_REPORT.md`, `FUTURE_WORK.md` перенесены из корня в `docs/`. |
| — | все модули | `cargo fmt --all` применён проектно-широко после переименований/рефакторинга — стиль унифицирован. |
| тесты | все модули | Юнит-тесты выросли с 16 до 66 (детекция версии, dual-bitness classifier, `read_bytes_up_to`, dispatch-table hint validation, `Bytecode::size` per-handler, `parse_hex_rva`, и т.д.). |

**Коммиты:** `cbb6186` (audit-driven overhaul: real detectors, dual-bitness, hardening), `d81cfbd` (CI + supply-chain security config) на `main`.

---

## 2. Что осталось (нельзя быстро — нужен реверс / образцы / архитектурное время)

Здесь приоритет: 🔴 critical · 🟠 high · 🟡 medium · ⚪ nice-to-have.

C1, C3, C4, S7, X1, Q6, Q7, Q9, Q10, Q11 закрыты — см. раздел 1a. Ниже — то, что реально осталось.

### 🟠 Q2 — Расширить `HandlerClassifier` (multi-byte fingerprints)

**Где:** `src/handler_classifier.rs::analyze_bytecode`.

**Проблема:** сейчас match только по первому байту (плюс bitness-gate на REX-префикс, см. X1 в разделе 1a) → покрывает ~20 x86-паттернов из 256 opcode-слотов; всё остальное — `UNKNOWN` (confidence 30). Таксономия к тому же x86-инструкционная (`MOV_REG_REG`, `ADD_REG_REG`, …), а не VMP-семантическая (`PUSH_VALUE`, `NOR_CHAIN`, …) — маппинг x86→VMP-семантика ещё предстоит. Для реальных VMP-handlers надо смотреть:
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

**Где:** `src/bytecode.rs::decode_operands`. Покрывает 8 handler-family names (`PUSH_REG`, `PUSH_VALUE`, `POP_MEMORY`, `ADD_REG`/`SUB_REG`/`XOR_REG`/`OR_REG`/`AND_REG`, `NOR_CHAIN`/`NAND_CHAIN`, `JMP`, `RET`). Всё остальное — `_ => {}` (silent no-op).

**Что нужно:** exhaustive match по всем handler-type строкам, генерируемым `handler_classifier::analyze_bytecode` (сейчас это x86-инструкционные имена вроде `MOV_REG_REG`, не совпадающие 1:1 с VMP-семантическими именами, которые ожидает `decode_operands` — согласовать после Q2). Иначе валидные handlers молча теряются.

**Оценка:** параллельно с Q2, ~1 день.

---

### 🟡 Q1 + Q13 — Real integration tests + fixtures

**Проблема:** 66 unit-тестов покрывают PE loader, version detector, dispatch-table locator, handler classifier и bytecode sizing — но все на **in-memory синтетических PE32/PE32+ фикстурах**, собранных вручную в тестах (`build_minimal_pe`-стиль хелперы). Ни одного реального VMP-protected сэмпла в тестовом наборе нет.

**Что нужно:**
- Директория `tests/fixtures/` с минимальным ассемблерным `.exe` (собрать через `link.exe /entry:main /subsystem:console`) — 4-8 KB достаточно для покрытия PE loader / va_to_offset / read_bytes на настоящем файле (а не только in-memory buffer).
- Один настоящий VMP-protected sample (можно с VMProtect Community/Free) в `tests/fixtures/vmp3_hello.exe` (проверить лицензию!).
- `tests/pe_loader.rs`, `tests/dispatch_table.rs` — integration-тесты, читающие файлы с диска.
- Property-tests (`proptest` crate) для `OpcodeCryptor::decrypt`/`update_crc` (round-trip invariants).

**Оценка:** 3-5 дней.

---

### ⚪ Q14 — Sanity против command-injection (S-lite)

**Где:** `src/dispatch_extractor_py.rs` — `Command::new(python_bin).arg(&script_path).arg(binary_path).arg(...)`. `binary_path` — это `binary.path` (сохранённый `path.as_ref().to_string_lossy()` из `pe_loader.rs`).

**Проблема:** пробелы/quotes в пути к бинарнику передадутся Python как аргумент корректно (мы используем `Command::arg`, не shell). Command injection не грозит. Но:
- Стоит валидировать что `binary_path` существует перед вызовом (сейчас Python упадёт с внутренней ошибкой).
- Логгировать полную command-line для reproducibility.

**Оценка:** 20 мин.

---

### ⚪ Q15 — Убрать зависимость от Python subprocess

**Идея:** заменить `unicorn_extractor.py` (скрипт всё ещё не входит в репозиторий) на прямой crate `unicorn-engine` (Rust bindings). Устраняет:
- необходимость Python в runtime,
- JSON-сериализацию через temp-файл (медленно),
- проблему "script not found".

**Проблема:** `unicorn-engine` требует C-библиотеки Unicorn на системе (Linux — `libunicorn-dev`; Windows — вручную собранный DLL). MSVC build может быть болезненным.

**Оценка:** 3-5 дней с проработкой Windows build.

---

### ⚪ X-new — Подключить `OpcodeCryptor` / `ALUReconstructor` к основному пайплайну

**Где:** `src/decrypt.rs` (`OpcodeCryptor`, CRC-based operand decryption), `src/alu.rs` (`ALUReconstructor`, NOR/NAND → ALU op reconstruction).

**Проблема:** оба модуля реализованы и покрыты юнит-тестами, но не вызываются из `VmpDevirtualizer::decode_instruction` / `devirtualize_range` в `src/lib.rs` — мёртвый код с точки зрения пайплайна.

**Что нужно:** дождаться Q2 (VMP-семантическая таксономия у `HandlerClassifier`), затем подключить `OpcodeCryptor` к операндам NOR/NAND-хендлеров и `ALUReconstructor` к декодированию цепочек в `decode_instruction`.

**Оценка:** зависит от Q2/Q3, отдельно — 1-2 дня интеграции.

---

### ⚪ X-new — End-to-end валидация на реальных x86 (32-бит) VMP-сэмплах

**Где:** dual-bitness код (`Bitness` в `pe_loader.rs`, `xor_key_analyzer.rs`, `handler_classifier.rs`, см. X1 в разделе 1a).

**Проблема:** dual-bitness путь компилируется и проходит структурные юнит-тесты (bitness-gated REX handling, entry-size 4 vs 8), но ни один живой 32-битный VMP-protected бинарник ещё не анализировался этим кодом end-to-end.

**Что нужно:** собрать/найти VMP-protected x86 (не x64) sample и прогнать полный пайплайн (`VmpDevirtualizer::new` → classify → devirtualize_range), сравнить с ожидаемым.

**Оценка:** 1 день при наличии образца.

---

## 3. Приоритизированный roadmap

### Спринт 1 (завершён) — «Честный релиз 0.2»
- ~~C1, C3, C4~~ — устранена архитектурная ложь: реальный VMP1/2 detect (скоринговый каскад), реальный `size()`, убран hardcoded RVA. См. `cbb6186`.
- ~~Q9~~ — README переписан с фактическими цифрами.
- ~~Q11~~ — корень реорганизован, отчёты перенесены в `docs/`.

### Спринт 2 (частично завершён) — «Полное покрытие handlers»
- Q2, Q4 — **осталось**: реальный table-driven VMP-семантический классификатор + exhaustive `decode_operands`.
- Q3 — **осталось**: символический ALU decompose (сейчас dummy stack-slot имена).
- ~~S7~~ — bounds-safe чтение handler bytes сделано (`read_bytes_up_to`). См. `cbb6186`.

### Спринт 3 (завершён) — «Инфраструктура»
- ~~Q10~~ — CI + cargo-audit + cargo-deny + rustfmt/clippy configs добавлены. См. `d81cfbd`.
- Q1/Q13 — **осталось**: integration tests + real-file/real-sample fixtures (текущие 66 тестов — все in-memory синтетика).
- ~~Q7~~ — `unicorn_*` переименованы (`xor_key_analyzer.rs`, `dispatch_extractor_py.rs`). См. `cbb6186`.

### Спринт 4 (2-3 недели) — «Полировка» (не начат)
- Q15 — оценка миграции на Rust `unicorn-engine`.
- Q14 — command-injection sanity + reproducibility logging.
- X-new — подключить `OpcodeCryptor`/`ALUReconstructor` к пайплайну (после Q2/Q3).
- X-new — end-to-end валидация на реальном x86 VMP-сэмпле.
- Documentation pass (rustdoc examples для публичных API).

---

## 4. Ссылки на код

- Cargo.toml `deps`: [D:\GitHub\Rust_Projects\VM-Protect-Research\Cargo.toml](./Cargo.toml)
- Архитектурный проход: коммиты `cbb6186` (audit-driven overhaul: real detectors, dual-bitness, hardening), `d81cfbd` (CI + supply-chain security) на `main`.
- Auto memory ruflo: `C:\Users\Platon\.claude\projects\D--GitHub-Rust-Projects-VM-Protect-Research\memory\` — читается в будущие сессии.

---

*Отчёт обновлён Claude Code (Sonnet 5) в рамках сессии 46b758ca на 2026-07-26 — актуализация после архитектурного прохода `cbb6186`/`d81cfbd`.*
