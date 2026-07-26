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

**Reference taxonomy (cross-validated 2026-07-26):**

Собрана из двух независимых open-source девиртуализаторов, оба **GPL-3.0** (использовать только как reference, не копировать код). Обе базы совпадают на ядре handlers и покрывают VMP 3.x x64.

Источники:
- `0xnobody/vmpattack` — `VMPAttack/vm_instruction_set.hpp`
- `can1357/NoVmp` (2163★) — `NoVmp/vmprotect/architecture.cpp`, `il2vtil.cpp`

Комбинированный список ≈35 VMP-semantic handlers:

| Категория | Handlers |
|---|---|
| Data movement (VM-stack) | `POP`, `POPSTK`, `PUSH`, `PUSHSTK`, `PUSHREG`, `POPREG` |
| Load/Store (VM-context / memory) | `LDD`, `STR` |
| VSP manipulation | `VSETVSP` (NoVmp) |
| Arithmetic base | `ADD`, `DIV`, `IDIV`, `MUL`, `IMUL` |
| Logic primitives (De Morgan) | `NAND`, `NOR` — комбинациями дают `AND`/`OR`/`XOR`/`NOT`/`SUB` |
| Shifts / rotates | `SHL`, `SHR`, `SHLD`, `SHRD`, `RCL`, `RCR` |
| Flags | `POPF` |
| System | `RDTSC`, `CPUID` (`VCPUID` / `VCPUIDX`), `LOCKOR`, `VPUSHCR0`, `VPUSHCR3` |
| Control-flow | `VJMP` (in-VM branch), `RET`, `VMEXIT` |
| Escape / meta | `VEMIT` (raw x86 emit), `VEXEC` (nested VM entry), `VNOP`, `VUNK` |

**Готовый план для Q2-subagent (когда возьмёмся):**
1. Ввести `enum VmpSemantic` с этими ~35 вариантами в `src/handler_classifier.rs`.
2. Расширить `HandlerClassification` полем `vmp_semantic: Option<VmpSemantic>` (не ломает API — `handler_type: String` остаётся fallback).
3. Реализовать multi-instruction matcher для 6-10 самых distinctive шаблонов (POP, PUSH-imm, PUSH-reg, NAND, NOR, VMEXIT, RET, VJMP) — паттерны VMP pipeline (`MOV reg,[VSP]` + `ADD VSP,size` + `MOV reg,[VIP]` + `MOV [CTX+reg],reg` = POP; и т.д.). Паттерны пишутся с нуля по описаниям — не копипаста из GPL.
4. Fallback на существующие x86-instruction-level labels для неопознанных handlers.
5. Unit-тесты на синтетических handler-body последовательностях.

**Что НЕЛЬЗЯ верифицировать без sample-а:** true-positive rate на реальных VMP 3.x бинарниках. Требуется real-sample validation set (~5-10 разных VMP-protected `.exe`) — открытый пункт.

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

### ✅ Спринт 1 (завершён) — «Честный релиз 0.2»
- C1, C3, C4 — устранена архитектурная ложь. См. `cbb6186`.
- Q9, Q11 — README + docs reorg. См. `cbb6186`.

### ✅ Спринт 3 (завершён) — «Инфраструктура»
- Q10 — CI + cargo-audit + cargo-deny + rustfmt/clippy. См. `d81cfbd`.
- Q7 — `unicorn_*` переименованы. См. `cbb6186`.
- S7 — bounds-safe handler read. См. `cbb6186`.
- CLI: `-v` collision fix + regression-guard test. См. `2ce88ec`.

### 🔴 Findings из живого запуска на `clmods.dll` (2026-07-26)

Реальный запуск CLI на не-VMP-бинарнике выявил три недоработки поверх известных Q2/Q3/Q4:

**F1 — `Default VIP 0x140001000` в `src/bin/cli.rs` — hardcoded, часто невалиден.**
На реальном DLL с иным image_base падает `Invalid VA: 0x140001000` и `Decoded 0 instructions`. Фикс: дефолтить в entry point PE или в первый адрес `.text` через `PEBinary`, если пользователь не указал `--vip`. Оценка: 30 мин.

**F2 — Non-VMP бинарник даёт misleading выхлоп** (`Detected VMP version: Unknown`, `confidence: 35/100`, потом попытка devirtualize).
Фикс: при `VmpVersion::Unknown` + confidence < 40 + dispatch table не найден → exit(2) с ясным сообщением «Not a VMP-protected binary (or version below detection threshold). Use `--dispatch-rva` if you have a known-good hint.». Не делать devirtualize_range на этом пути. Оценка: 20 мин.

**F3 — Нет способа переопределить detected version.**
Полезно для research: `--force-version vmp35` чтобы прогнать хотя бы partial pipeline. Оценка: 30 мин.

### 🟠 Спринт 2 (в работе) — «Полное покрытие handlers»
- Q2 — реальный VMP-семантический классификатор (~35 handlers, taxonomy готова, см. §Q2).
- Q4 — exhaustive `decode_operands` под Q2 taxonomy.
- Q3 — символический ALU decompose (dummy → VSP slot names).

### 🟡 Спринт 4 (не начат) — «Полировка»
- Q15 — Rust `unicorn-engine` вместо Python subprocess.
- Q14 — command-injection sanity + reproducibility logging.
- X-new/A — подключить `OpcodeCryptor` в `Bytecode::decode_operands` (сейчас dead-code-in-pipeline).
- X-new/B — подключить `ALUReconstructor` в decode-pipeline после Q3.
- X-new/C — end-to-end валидация на реальном x86 VMP-сэмпле.
- X-new/D — rustdoc examples для публичного API.

---

## 5. Недельный roadmap для следующей сессии (реалистичный)

Цель: получить рабочий инструмент, честно анализирующий простой VMP-3 sample (hello world под VMP), с выхлопом узнаваемых handler-имён.

| День | Задача | Как делать | Оценка | Зависимости |
|---|---|---|---|---|
| **1** | F1+F2+F3 — CLI полировка | 1 subagent (мелкий, ~30 мин фоном): дефолт VIP из entry_point, graceful exit на non-VMP, `--force-version`. Плюс: интеграционный тест который запускает бинарь через `assert_cmd` на mock-PE fixture (ловит будущие CLI-регрессии как `-v` collision). | 2 ч | — |
| **2** | Q2-lite — VmpSemantic enum + 6 базовых matchers | 1 subagent: `VmpSemantic { Pop, PushImm, PushReg, Nand, Nor, Ret, Vmexit, Vjmp, Unknown }`, `HandlerClassification.vmp_semantic: Option<VmpSemantic>`, multi-instruction matcher для этих 6 (VSP-fetch → operand → CTX-store etc). Fallback на существующие x86-labels. Тесты на синтетических handler-body. | 4-6 ч | Taxonomy §Q2 |
| **3** | Q2-full — оставшиеся ~29 handlers + Q4 (`decode_operands` refresh) | 1 subagent: расширяем matcher-таблицу до полной taxonomy; обновляем `decode_operands` под новые VmpSemantic. | 6-8 ч | День 2 |
| **4** | X-new/A — подключить `OpcodeCryptor` в pipeline | Пишу сам (не subagent): в `decode_operands` вызвать `OpcodeCryptor::decrypt_operands` для VMP-версий которые шифруют immediate. CRC-init из VIP handler-а. Тесты. | 4 ч | Q2 |
| **5** | Q3 — символический ALU decompose | 1 subagent: `VspSlot(offset)` вместо dummy строк; De Morgan → синтезированный `Add/Sub/And/Or/Xor`; вызов из `decode_operands` для NOR/NAND. Тесты. | 6-8 ч | Q2 |
| **6** | X-new/C — real-sample validation | Собираю 3-5 VMP-3 sample-бинарников (можно с VMProtect Free/Trial на простом hello-world). Прогоняю CLI. Ловим bugs. Правлю. | 6 ч | Дни 1-5 |
| **7** | X-new/B — `ALUReconstructor` в pipeline + доработка + release 0.2 | Подключаем ALUReconstructor. Пишу CHANGELOG. Тегаю v0.2.0. Пушим CI зелёный. | 4 ч | Дни 1-6 |

**Итого:** ~40-45 часов работы с subagent-ассистированием. За календарную неделю (5 рабочих дней по 8 часов) реалистично закрыть дни 1-5. Дни 6-7 могут уползти во вторую неделю если валидация вскроет глубокие баги (обычно вскрывает).

**Что получишь на выходе (v0.2.0):**
- CLI, который на простом VMP-3 hello world выдаёт правильные VMP-semantic handler-имена вместо `MOV_REG_MEM`.
- Devirtualize_range шагает по реальным instruction-длинам, decrypts operand через `OpcodeCryptor`, восстанавливает `ADD/SUB/AND/OR/XOR` из NOR/NAND-цепочек.
- Graceful exit на не-VMP бинарниках.
- Все 66+ юнит-тестов + новые integration-тесты (`assert_cmd` на mock-PE).
- CI зелёный на Windows + Linux + security audit.
- Documented API + пример в README.

**Что НЕ получишь:**
- Полное покрытие VMP 3.7+ (merged handlers) — отдельная неделя, нужен sample именно 3.7+.
- Real symbolic execution engine (не mini-symbolic — full Z3/etc).
- Handler `LDD/STR/MUL/DIV/RDTSC/CPUID/LOCKOR/VPUSHCR*` могут остаться partial.

---

## 6. Ссылки на код

- `Cargo.toml`, `Cargo.lock` — deps на latest stable (2026-07-26).
- Коммиты в текущей сессии на `main`:
  - `cbb6186` — audit-driven overhaul: real detectors, dual-bitness, hardening
  - `d81cfbd` — CI + supply-chain security config
  - `412a805` — sync docs + migrate deny.toml to cargo-deny schema v2
  - `3cf2660` — Q2: captured cross-validated VMP handler taxonomy
  - `2ce88ec` — fix clap short-flag collision on `-v` + regression-guard test
- Auto memory (для будущих сессий): `C:\Users\Platon\.claude\projects\D--GitHub-Rust-Projects-VM-Protect-Research\memory\`.
- Reference sources для Q2 (GPL-3.0, READ ONLY): `0xnobody/vmpattack`, `can1357/NoVmp`.

---

*Отчёт обновлён Claude Code (Opus 4.7) в рамках сессии 46b758ca на 2026-07-26 — актуализирован после live-запуска CLI на не-VMP бинарнике, добавлен реалистичный недельный план для следующей сессии.*
