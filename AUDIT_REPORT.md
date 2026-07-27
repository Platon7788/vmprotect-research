# VMP Devirtualizer — Audit Report

**Дата:** 2026-07-26 (актуализировано 2026-07-27)
**Ветка:** main · **Rust:** 1.97.1 · **Проект:** vmp_devirt 0.1.0

---

## 0. TL;DR

| Метрика | Значение |
|---|---|
| Строк Rust | 4 829 (`wc -l src/*.rs src/bin/*.rs`, 2026-07-27) |
| Модулей | 13 (`src/handler_semantic.rs` добавлен в `06ae816`) |
| Тестов | 111 pass / 0 fail — 105 lib + 1 bin + 5 integration (`cargo test --all-targets`, было 66/0, до того 16/0) |
| Clippy warnings | 0 (`cargo clippy --all-targets`) |
| Build (dev + release) | ✓ |
| CI | ⛔ отключён — проект локальный, GitHub Actions удалён (2026-07-27); все 4 gate'а (`build`/`test`/`clippy -D warnings`/`fmt --check`) обязаны прогоняться локально перед коммитом |
| Deps latest | ✓ (goblin 0.10.7, clap 4.6.4, serde 1.0.229, serde_json 1.0.151, anyhow 1.0.104, log 0.4.33, env_logger 0.11.11) |

> Строки/модули/тесты в этой таблице — актуализировано 2026-07-27 (см. раздел 1b). Остальной текст ниже сохранён как исторический след сессии 2026-07-26 и помечен там, где он устарел.

**Быстрые фиксы применены** (см. раздел 1). Начиная с той сессии раздел 1 также включал архитектурные фиксы C1/C3/C4/X1 и инфраструктурные Q6/Q7/Q10/Q11, ранее числившиеся в разделе 2 — они landed в коммитах `cbb6186` (audit-driven overhaul: real detectors, dual-bitness, hardening) и `d81cfbd` (CI + supply-chain security) на `main`. С тех пор landed ещё 6 коммитов (`b95246d`, `06ae816`, `64288a4`, `e586638`, `e5fa959`, `5744974`) — см. **раздел 1b** для того, что они закрыли. **Остальное** — в разделе 2 (что доделывать).

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
| Q10 | ~~`.github/workflows/ci.yml`~~, `rustfmt.toml`, `clippy.toml` | CI добавлен и позже удалён — см. `2026-07-27`, проект переведён на local-only gate discipline. Инструментальные конфиги (`rustfmt.toml`, `clippy.toml`, `deny.toml`) остаются под git — гарантируют одинаковое поведение локальных прогонов. |
| Q11 | `docs/` | `IMPLEMENTATION_COMPLETE.md`, `VALIDATION_REPORT.md`, `UNICORN_IMPLEMENTATION_REPORT.md`, `FUTURE_WORK.md` перенесены из корня в `docs/`. |
| — | все модули | `cargo fmt --all` применён проектно-широко после переименований/рефакторинга — стиль унифицирован. |
| тесты | все модули | Юнит-тесты выросли с 16 до 66 (детекция версии, dual-bitness classifier, `read_bytes_up_to`, dispatch-table hint validation, `Bytecode::size` per-handler, `parse_hex_rva`, и т.д.). |

**Коммиты:** `cbb6186` (audit-driven overhaul: real detectors, dual-bitness, hardening), `d81cfbd` (CI + supply-chain security config) на `main`.

---

## 1b. Что доделано после недельного плана (`b95246d` … `5744974`) ✓

Шесть коммитов landed на `main` после раздела 5 (недельный roadmap), закрывающие Дни 1-5 целиком плюс отдельный audit-driven проход (Commits A-C). Актуализировано 2026-07-27.

| Коммит | Что сделано |
|---|---|
| `b95246d` (День 1) | F1: дефолт `--vip` = PE entry point вместо hardcoded `0x140001000`. F2: non-VMP бинарник → `exit(2)` (`EXIT_NOT_VMP`) с actionable stderr вместо попытки devirtualize. F3: флаг `--force-version <vmp1\|vmp2\|vmp30\|vmp35\|vmp36>` для research-override. Плюс `PEBinary::entry_point_va()`, `VmpVersion` re-export на root крейта, интеграционный тест-харнесс (`tests/cli.rs` + `tests/common/mod.rs`) через `assert_cmd`. |
| `06ae816` (Q2, Дни 2-3) | `enum VmpSemantic` (~35 вариантов), `SemanticMatcher` с 8 distinctive fingerprints (Rdtsc, Cpuid, Vmexit, Nand, Nor, Push, Pop, Vjmp), поле `vmp_semantic: Option<VmpSemantic>` на `HandlerClassification` (`#[serde(default)]`, backward-compatible), 20+ юнит-тестов в `src/handler_semantic_tests.rs` (`#[path]`-included в `handler_semantic.rs`). Это **частичная** реализация плана из §Q2 — 8 из ~35 handler-matchers. |
| `64288a4` (Дни 4-5) | `Bytecode::decode_operands` подключён к `OpcodeCryptor` (**breaking API**: теперь принимает `&mut OpcodeCryptor`). `ALUReconstructor::reconstruct_alu_chains` подключён в `lib.rs::devirtualize_range`. `alu::decompose_chain` теперь возвращает `"vsp+0"`/`"vsp+8"` вместо `"stack_val_1"`/`"stack_val_2"`. `DecodedInstruction.alu_op: Option<ALUOp>` — новое поле. |
| `e586638` (Commit A — 7 correctness bugs) | Sign-extension в H_JMP (negative rel32 давал +4GB прыжки вместо backward jump). `read_imm` shift-overflow при size ≥ 9 (debug panic / release UB на malicious opcode table). Off-by-one в dispatch-table pattern scan (ровно 256×entry_size секции не детектились). `OpcodeTable::from_json` панera на коротких `opcode_byte` строках → теперь `Err`. 1-NOR chain → `ALUOp::Not` терялся молча → `reconstruct_alu_chains` теперь использует `match_chain` для всех зарегистрированных длин цепочек. `version::section_at_va` клампится в `min(virtual_size, size_of_raw_data)`, как и `pe_loader::locate_section`. `entry_point_bytes` использует `read_bytes_up_to` — короткие entry-секции больше не гасят все VMP1-эвристики. |
| `e5fa959` (Commit B — test quality) | Удалён тавтологичный `test_find_extractor_script`, переписан на реальный assert. Ужесточены assertion'ы `assert_ne!(_, Some(X))` → `assert_eq!(_, None)` (мисклассификации больше не проходят молча). `test_crc_update` пиннит точную формулу `crc*31 + val`. Round-trip тесты для `decrypt_value_u32`/`decrypt_value_u64`. |
| `5744974` (Commit C — architecture cleanup) | Дедуп PE-фикстуры: `pe_loader::test_util::build_minimal_pe` теперь общий builder (был скопирован в 3 местах). `alu::HandlerContext` и `XorKeyAnalyzer::new`+поля удалены (dead public API); `XorKeyAnalyzer` — bare marker type. Crate-root re-export `DispatchExtractorPy`/`DispatchEntry` убран (доступ через `vmp_devirt::dispatch_extractor_py::*`, подготовка к Q15). `VmpDevirtualizer::force_version`/`looks_like_vmp` доведены до финального вида. |

**Итог:** Дни 1-5 недельного плана (раздел 5) закрыты целиком; отдельно прошёл audit-driven проход (7 correctness bugs + test-quality sweep + architecture cleanup) поверх них. Тестов: 66 → 111.

---

## 2. Что осталось (нельзя быстро — нужен реверс / образцы / архитектурное время)

Здесь приоритет: 🔴 critical · 🟠 high · 🟡 medium · ⚪ nice-to-have.

C1, C3, C4, S7, X1, Q6, Q7, Q9, Q10, Q11 закрыты — см. раздел 1a. Ниже — то, что реально осталось.

### 🟡 Q2 — Расширить `HandlerClassifier` (multi-byte fingerprints) — ЧАСТИЧНО ЗАКРЫТО (`06ae816`)

**Где:** `src/handler_classifier.rs::analyze_bytecode`, `src/handler_semantic.rs` (новый модуль).

**Что сделано (`06ae816`):**
- `enum VmpSemantic` в `src/handler_semantic.rs` — ~35 вариантов (Pop, Popstk, Push, Pushstk, Pushreg, Popreg, Ldd, Str, Vsetvsp, Add, Div, Idiv, Mul, Imul, Nand, Nor, Shl/Shr/Shld/Shrd/Rcl/Rcr, Popf, Rdtsc, Cpuid, Vjmp, Vmexit, …).
- `struct SemanticMatcher` с multi-instruction matcher для 8 самых distinctive fingerprints: `Rdtsc`, `Cpuid`, `Vmexit`, `Nand`, `Nor`, `Push`, `Pop`, `Vjmp`.
- Поле `vmp_semantic: Option<VmpSemantic>` на `HandlerClassification` — `#[serde(default)]`, add-only, не ломает существующий `handler_type: String`.
- 20+ юнит-тестов на синтетических handler-body в `src/handler_semantic_tests.rs`.
- Тесты дополнительно ужесточены в `e5fa959` — `assert_eq!(_, None)` вместо `assert_ne!(_, Some(X))` там, где раньше мисклассификация могла тихо проходить.

**Что осталось:**
- ~27 из ~35 handler-matchers из таксономии ниже ещё не реализованы (LDD, STR, MUL, DIV, IDIV, IMUL, shifts/rotates, RDTSC/CPUID уже есть, LOCKOR, VPUSHCR0/CR3, RET, VEMIT, VEXEC, VNOP, VUNK и т.д.).
- True-positive rate на реальных VMP 3.x бинарниках не верифицирован — нужен real-sample validation set (см. Q4 в разделе 5, Дни 6-7, всё ещё открыт).
- Старая x86-instruction-level таксономия (`handler_type: String`, напр. `MOV_REG_REG`) остаётся как fallback и не удалена — так и задумано (add-only migration).

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

**Исторический план для Q2-subagent (закрыт `06ae816`, оставлен для аудита):**
1. ✅ Ввести `enum VmpSemantic` с этими ~35 вариантами — реализовано в `src/handler_semantic.rs` (не в `handler_classifier.rs`, как планировалось изначально — отдельный модуль).
2. ✅ Расширить `HandlerClassification` полем `vmp_semantic: Option<VmpSemantic>` — сделано, `handler_type: String` остаётся fallback.
3. 🟡 Реализовать multi-instruction matcher для 6-10 самых distinctive шаблонов — сделано **8 из 10** (Pop, Push, Nand, Nor, Vmexit, Vjmp, Rdtsc, Cpuid); Ret и Push-imm/Push-reg differentiation не реализованы отдельно.
4. Fallback на существующие x86-instruction-level labels для неопознанных handlers — не требовалось отдельной реализации, `handler_type: String` уже был fallback по дизайну поля #2.
5. ✅ Unit-тесты на синтетических handler-body последовательностях — 20+ тестов в `src/handler_semantic_tests.rs`.

**Что НЕЛЬЗЯ верифицировать без sample-а:** true-positive rate на реальных VMP 3.x бинарниках. Требуется real-sample validation set (~5-10 разных VMP-protected `.exe`) — открытый пункт, см. раздел 5 (Дни 6-7).

---

### 🟡 Q3 — Реальный `alu::decompose_chain` — ЧАСТИЧНО ЗАКРЫТО в `64288a4` и `e586638`

**Где:** `src/alu.rs::decompose_chain` (было `src/alu.rs:74-83`, возвращало dummy строки `"stack_val_1"`, `"stack_val_2"`).

**Что сделано:**
- `64288a4`: `decompose_chain` теперь возвращает символические имена стек-слотов `"vsp+0"` / `"vsp+8"` вместо dummy-строк (жёстко закодировано под x64-конвенцию — см. doc-comment на функции).
- `64288a4`: `ALUReconstructor::reconstruct_alu_chains` подключён в `lib.rs::devirtualize_range`; результат пишется в новое поле `DecodedInstruction.alu_op: Option<ALUOp>`.
- `e586638`: 1-NOR chain → `ALUOp::Not` больше не терялся молча — `reconstruct_alu_chains` использует `match_chain` (не `decompose_chain` напрямую), которая обрабатывает все зарегистрированные длины цепочек, а не только 4-NOR.

**Что осталось:**
- Слоты жёстко захардкожены под x64 (`vsp+0`/`vsp+8`); x86-конвенция (`vsp+0`/`vsp+4`) не реализована.
- Реальная symbolic execution mini-engine для произвольных цепочек (не только распознанных 2-операндных De Morgan паттернов) — не начата.

**Оценка оставшегося:** несколько дней на x86 vsp-слоты + symbolic engine, если понадобится за рамки текущих зарегистрированных chain-паттернов.

---

### 🟠 Q4 — Расширить `Bytecode::decode_operands`

**Где:** `src/bytecode.rs::decode_operands`. Покрывает 8 handler-family names (`PUSH_REG`, `PUSH_VALUE`, `POP_MEMORY`, `ADD_REG`/`SUB_REG`/`XOR_REG`/`OR_REG`/`AND_REG`, `NOR_CHAIN`/`NAND_CHAIN`, `JMP`, `RET`). Всё остальное — `_ => {}` (silent no-op).

**Что изменилось (`64288a4`, `e586638`) — но задача не закрыта:**
- **API-breaking change**: `decode_operands` теперь принимает `handler: &Handler, cryptor: &mut OpcodeCryptor` (было — только `handler`). Операнды VMP-версий с CRC-шифрованием теперь дешифруются через `OpcodeCryptor` перед возвратом.
- NOR_CHAIN/NAND_CHAIN operand-byte routing по-прежнему no-op — задокументировано инлайн-комментарием в коде, не тихий баг, а осознанный gap (ALU-семантика восстанавливается отдельно через `alu::reconstruct_alu_chains`, не через `decode_operands`).
- `OpcodeTable::from_json` теперь panic-safe: короткие `opcode_byte` строки возвращают `Err` вместо паники (`e586638`).
- `read_imm` теперь отклоняет `size > 8` явной ошибкой вместо debug-panic / release-UB на shift-overflow (`e586638`).

**Commit M — real VMP crypto per version (частичное закрытие):**
- `crc*31+val` placeholder заменён на `enum CryptoScheme { None, Placeholder, Vmp2Rolling, Vmp3PerHandler }` с `CryptoScheme::for_version()` для выбора по `VmpVersion`.
- `OpcodeCryptor::new_with_scheme(scheme)` — новый preferred конструктор; `new()` сохранён (Placeholder) для backward compatibility.
- `Vmp2Rolling` = XOR-key -> NEG -> ROL 5 -> INC + XOR-key update (из back.engineering VMP 2 write-up, gmh5225 GitHub mirror).
- `Vmp3PerHandler` = XOR-key -> ROR 1 -> NOT + XOR-key update (из r0da VMP-3 Part 3 + vxcall VMProtect 3.8.1). Per-handler op selection ещё не реализован — применяется DEFAULT op set.
- `devirtualize_range` теперь выбирает scheme через `for_version` и логгирует выбор.
- +11 unit-тестов: routing table, invertibility (encrypt-then-decrypt) на Vmp2/Vmp3, N-step determinism на всех схемах, init_from_section seed check.

**Что осталось:**
- Validation против реальных VMP-decrypted operand-streams (Days 6-7, blocked без sample-бинарников).
- Per-handler cryptor op selection для Vmp3 (нужна дизассемблированная handler-body — depend on Commit K register-role work).
- Exhaustive match по всем handler-type строкам, генерируемым `handler_classifier::analyze_bytecode` — по-прежнему открыто, согласование с Q2 VMP-семантической таксономией (`VmpSemantic`) не выполнено — `decode_operands` всё ещё matches на старые x86-instruction-level имена (`MOV_REG_REG` и т.д.), не на `VmpSemantic`.

**Оценка:** параллельно с оставшимися Q2 matchers, ~1 день.

---

### 🟡 Q1 + Q13 — Real integration tests + fixtures — ЧАСТИЧНО ЗАКРЫТО в `b95246d`

**Что сделано:** интеграционный тест-харнесс `tests/cli.rs` + `tests/common/mod.rs` через `assert_cmd` landed в `b95246d` (5 тестов: F1 default VIP, F2 exit code 2, F3 force-version override + rejects unknown value, short-flag disambiguation regression guard). `5744974` дедуплицировал PE-фикстуру в общий `pe_loader::test_util::build_minimal_pe`, используемый и юнит-, и интеграционными тестами.

**Проблема, которая остаётся:** 111 тестов (105 lib + 1 bin + 5 integration) покрывают PE loader, version detector, dispatch-table locator, handler classifier, bytecode sizing и CLI-контракт — но всё ещё на **in-memory синтетических PE32/PE32+ фикстурах**. Ни одного реального VMP-protected сэмпла и ни одного настоящего `.exe`-файла на диске в тестовом наборе нет.

**Что нужно:**
- Директория `tests/fixtures/` с минимальным ассемблерным `.exe` (собрать через `link.exe /entry:main /subsystem:console`) — 4-8 KB достаточно для покрытия PE loader / va_to_offset / read_bytes на настоящем файле (а не только in-memory buffer).
- Один настоящий VMP-protected sample (можно с VMProtect Community/Free) в `tests/fixtures/vmp3_hello.exe` (проверить лицензию!).
- Property-tests (`proptest` crate) для `OpcodeCryptor::decrypt`/`update_crc` (round-trip invariants).

**Оценка оставшегося:** 2-4 дня (харнесс уже есть, не хватает файловых fixtures и real-sample).

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

### ✅ X-new — Подключить `OpcodeCryptor` / `ALUReconstructor` к основному пайплайну — ЗАКРЫТО в `64288a4`

**Было:** `src/decrypt.rs` (`OpcodeCryptor`, CRC-based operand decryption), `src/alu.rs` (`ALUReconstructor`, NOR/NAND → ALU op reconstruction) — реализованы и покрыты юнит-тестами, но не вызывались из пайплайна.

**Что сделано:** оба модуля подключены в `64288a4`:
- `OpcodeCryptor` — вызывается из `Bytecode::decode_operands` (`src/bytecode.rs`), которая теперь принимает `&mut OpcodeCryptor` как параметр (breaking API change, см. §Q4).
- `ALUReconstructor` — вызывается из `lib.rs::devirtualize_range` → `alu::reconstruct_alu_chains`, результат пишется в `DecodedInstruction.alu_op: Option<ALUOp>`.

Больше не мёртвый код с точки зрения пайплайна.

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
- Q10 — CI (позже удалён — local-only) + cargo-audit + cargo-deny + rustfmt/clippy. См. `d81cfbd` + удаление GitHub Actions от 2026-07-27.
- Q7 — `unicorn_*` переименованы. См. `cbb6186`.
- S7 — bounds-safe handler read. См. `cbb6186`.
- CLI: `-v` collision fix + regression-guard test. См. `2ce88ec`.

### ✅ Findings из живого запуска на `clmods.dll` (2026-07-26) — ЗАКРЫТО в `b95246d`

Реальный запуск CLI на не-VMP-бинарнике выявил три недоработки поверх известных Q2/Q3/Q4. Все три shipped в `b95246d` (День 1):

**F1 — `Default VIP 0x140001000` в `src/bin/cli.rs` — hardcoded, часто невалиден.** ✅
Фикс применён: `--vip` дефолтится в `PEBinary::entry_point_va()`, если пользователь не указал явно.

**F2 — Non-VMP бинарник даёт misleading выхлоп.** ✅
Фикс применён: `VmpDevirtualizer::looks_like_vmp()` гейтит пайплайн; на `false` — `exit(EXIT_NOT_VMP)` (код 2) с actionable stderr-сообщением про `--force-version`/`--dispatch-rva`. `devirtualize_range` на этом пути не вызывается.

**F3 — Нет способа переопределить detected version.** ✅
Фикс применён: флаг `--force-version <vmp1|vmp2|vmp30|vmp35|vmp36>`, применяется до логирования/гейта на версию.

### ✅ Спринт 2 (частично завершён) — «Полное покрытие handlers»
- Q2 — VMP-семантический классификатор: 8 из ~35 handlers, taxonomy готова. См. §Q2. **Частично** shipped `06ae816`.
- Q4 — exhaustive `decode_operands` под Q2 taxonomy: **не сделано**, API стал breaking (`&mut OpcodeCryptor`) в `64288a4`, но matching всё ещё на старых x86-labels. См. §Q4.
- Q3 — символический ALU decompose: `dummy → "vsp+0"/"vsp+8"` **сделано** `64288a4`; symbolic engine для произвольных цепочек — нет. См. §Q3.

### 🟡 Спринт 4 (частично завершён) — «Полировка»
- Q15 — Rust `unicorn-engine` вместо Python subprocess. Не начато.
- Q14 — command-injection sanity + reproducibility logging. Не начато.
- X-new/A — подключить `OpcodeCryptor` в `Bytecode::decode_operands`. ✅ shipped `64288a4`.
- X-new/B — подключить `ALUReconstructor` в decode-pipeline. ✅ shipped `64288a4` (не дожидались отдельного Q3-символьного движка — использована текущая `decompose_chain`).
- X-new/C — end-to-end валидация на реальном x86 VMP-сэмпле. Не начато — см. раздел 5, Дни 6-7 (по-прежнему заблокировано отсутствием сэмплов).
- X-new/D — rustdoc examples для публичного API. Не начато.

### 🟡 Новые pending-пункты, найденные аудитом (не пофикшены)

- **Version-detector tiebreaker** (`src/version.rs:226`) — `max_by(points, then top_priority)` не имеет детерминированного разрешения при полном совпадении и points, и top_priority: `Iterator::max_by` возвращает последний из равных максимумов, порядок в массиве `candidates` (`Vmp1, Vmp2, Vmp30, Vmp35, Vmp36Plus`) молча определяет исход. Не покрыто тестом на явный tie. Оценка: 1-2 часа (детерминировать явно + regression test).
- **Log-injection через section-имена** (`src/dispatch_table.rs`, вокруг строки 135, ветки `log::info!`/`log::warn!` в `locate`) — имена PE-секций читаются из файла (`section.name`) и попадают в лог без санитизации управляющих/ANSI-escape байт. Не RCE, но может искажать/подделывать лог-вывод при разборе malicious PE. Оценка: 30 мин (strip non-printable перед логированием).
- **Unchecked `image_base + rva`/`image_base + section.virtual_address` арифметика** — множественные точки в `src/dispatch_table.rs` (строки ~27, 116, 136, 228, 286, 305, 336), `src/handler_classifier.rs:308`, `src/pe_loader.rs` (строки ~415, 433) складывают `u64` без `checked_add`; malicious PE с `image_base`/`rva` близко к `u64::MAX` может вызвать panic в debug или silent wraparound в release. `pe_loader.rs` частично исправлен ранее (S1/S4, см. раздел 1), но новые сложения, добавленные в `64288a4`/`06ae816`/`e586638`, этот паттерн не наследуют. Оценка: 2-4 часа на аудит всех точек + `checked_add`/`saturating_add`.

---

## 5. Недельный roadmap для следующей сессии (реалистичный)

> **Дни 1-5 закрыты** (коммиты `b95246d`, `06ae816`, `64288a4` — см. раздел 1b для детального разбора того, что именно сделано против того, что планировалось). Таблица ниже сохранена как исходный план сессии 2026-07-26; актуальный статус — колонка "Факт" справа. **Дни 6-7 всё ещё открыты** — заблокированы отсутствием real VMP-3 sample-бинарников.

Цель: получить рабочий инструмент, честно анализирующий простой VMP-3 sample (hello world под VMP), с выхлопом узнаваемых handler-имён.

| День | Задача | Как делать | Оценка | Зависимости | Факт |
|---|---|---|---|---|---|
| **1** | F1+F2+F3 — CLI полировка | 1 subagent (мелкий, ~30 мин фоном): дефолт VIP из entry_point, graceful exit на non-VMP, `--force-version`. Плюс: интеграционный тест который запускает бинарь через `assert_cmd` на mock-PE fixture (ловит будущие CLI-регрессии как `-v` collision). | 2 ч | — | ✅ `b95246d` |
| **2** | Q2-lite — VmpSemantic enum + 6 базовых matchers | 1 subagent: `VmpSemantic { Pop, PushImm, PushReg, Nand, Nor, Ret, Vmexit, Vjmp, Unknown }`, `HandlerClassification.vmp_semantic: Option<VmpSemantic>`, multi-instruction matcher для этих 6 (VSP-fetch → operand → CTX-store etc). Fallback на существующие x86-labels. Тесты на синтетических handler-body. | 4-6 ч | Taxonomy §Q2 | ✅ `06ae816` (8 matchers вместо 6, другой набор — см. §Q2) |
| **3** | Q2-full — оставшиеся ~29 handlers + Q4 (`decode_operands` refresh) | 1 subagent: расширяем matcher-таблицу до полной taxonomy; обновляем `decode_operands` под новые VmpSemantic. | 6-8 ч | День 2 | 🟡 не сделано — только API-breaking смена сигнатуры `decode_operands` в `64288a4`, matcher-таблица не расширена |
| **4** | X-new/A — подключить `OpcodeCryptor` в pipeline | Пишу сам (не subagent): в `decode_operands` вызвать `OpcodeCryptor::decrypt_operands` для VMP-версий которые шифруют immediate. CRC-init из VIP handler-а. Тесты. | 4 ч | Q2 | ✅ `64288a4` |
| **5** | Q3 — символический ALU decompose | 1 subagent: `VspSlot(offset)` вместо dummy строк; De Morgan → синтезированный `Add/Sub/And/Or/Xor`; вызов из `decode_operands` для NOR/NAND. Тесты. | 6-8 ч | Q2 | ✅ частично `64288a4`+`e586638` (строковые слоты, не typed `VspSlot`; см. §Q3) |
| **6** | X-new/C — real-sample validation | Собираю 3-5 VMP-3 sample-бинарников (можно с VMProtect Free/Trial на простом hello-world). Прогоняю CLI. Ловим bugs. Правлю. | 6 ч | Дни 1-5 | ⬜ ОТКРЫТО — заблокировано отсутствием sample-бинарников |
| **7** | X-new/B — `ALUReconstructor` в pipeline + доработка + release 0.2 | Подключаем ALUReconstructor. Пишу CHANGELOG. Тегаю v0.2.0. Локальные gate'ы (build/test/clippy/fmt) чистые. | 4 ч | Дни 1-6 | 🟡 ALUReconstructor подключён (день 4-5, раньше плана); CHANGELOG.md создан отдельным Commit D; v0.2.0 tag не поставлен |

**Итого:** ~40-45 часов работы с subagent-ассистированием. За календарную неделю (5 рабочих дней по 8 часов) реалистично закрыть дни 1-5. Дни 6-7 могут уползти во вторую неделю если валидация вскроет глубокие баги (обычно вскрывает).

**Что получишь на выходе (v0.2.0):**
- CLI, который на простом VMP-3 hello world выдаёт правильные VMP-semantic handler-имена вместо `MOV_REG_MEM`.
- Devirtualize_range шагает по реальным instruction-длинам, decrypts operand через `OpcodeCryptor`, восстанавливает `ADD/SUB/AND/OR/XOR` из NOR/NAND-цепочек.
- Graceful exit на не-VMP бинарниках.
- Все 66+ юнит-тестов + новые integration-тесты (`assert_cmd` на mock-PE).
- Локальный gate discipline: `build`/`test --all-targets`/`clippy --all-targets -- -D warnings`/`fmt --check` чистые перед каждым коммитом (проект local-only, CI на GitHub Actions отключён 2026-07-27).
- Documented API + пример в README.

**Что НЕ получишь:**
- Полное покрытие VMP 3.7+ (merged handlers) — отдельная неделя, нужен sample именно 3.7+.
- Real symbolic execution engine (не mini-symbolic — full Z3/etc).
- Handler `LDD/STR/MUL/DIV/RDTSC/CPUID/LOCKOR/VPUSHCR*` могут остаться partial.

---

## 6. Ссылки на код

- `Cargo.toml`, `Cargo.lock` — deps на latest stable (2026-07-26).
- Коммиты на `main` (сессия 2026-07-26):
  - `cbb6186` — audit-driven overhaul: real detectors, dual-bitness, hardening
  - `d81cfbd` — CI + supply-chain security config
  - `412a805` — sync docs + migrate deny.toml to cargo-deny schema v2
  - `3cf2660` — Q2: captured cross-validated VMP handler taxonomy
  - `2ce88ec` — fix clap short-flag collision on `-v` + regression-guard test
- Коммиты на `main` (сессия 2026-07-27, см. раздел 1b и §Q2/§Q3/§Q4/X-new выше):
  - `b95246d` — Day 1: F1/F2/F3 + assert_cmd integration test
  - `06ae816` — Q2 (Days 2-3): VMP-semantic classifier layer
  - `64288a4` — Days 4-5: wire OpcodeCryptor + ALU reconstructor into pipeline
  - `e586638` — Commit A: fix 7 correctness bugs surfaced by audit
  - `e5fa959` — Commit B: test-quality sweep
  - `5744974` — Commit C: architecture cleanup: dedupe PE fixture, extract logic, kill dead API
- Auto memory (для будущих сессий): `C:\Users\Platon\.claude\projects\D--GitHub-Rust-Projects-VM-Protect-Research\memory\`.
- Reference sources для Q2 (GPL-3.0, READ ONLY): `0xnobody/vmpattack`, `can1357/NoVmp`.

---

*Отчёт впервые собран Claude Code (Opus 4.7) в рамках сессии 46b758ca на 2026-07-26 — актуализирован после live-запуска CLI на не-VMP бинарнике, добавлен реалистичный недельный план для следующей сессии. Ревизия 2026-07-27 (Commit D, docs sync): сверены 6 дополнительных коммитов, закрывших Дни 1-5 недельного плана плюс отдельный audit-driven проход (Commits A-C — 7 correctness fixes, test-quality sweep, architecture cleanup). Строки/модули/тесты в разделе 0 пересчитаны напрямую (`wc -l`, `cargo test --all-targets`), не оценены.*
