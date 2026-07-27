# VMP Devirtualizer — Audit Report

**Дата:** 2026-07-26 (актуализировано 2026-07-27 после T/U/V audit remediation)
**Ветка:** main · **Rust:** 1.97.1 · **Проект:** vmp_devirt 0.1.0

---

## 0. TL;DR

| Метрика | Значение |
|---|---|
| Строк Rust | 14 102 (`wc -l src/*.rs src/bin/*.rs`, 2026-07-27, после Commit V) |
| Модулей | 39 файлов (`src/*.rs` + `src/bin/cli.rs`; было 13 на момент 2026-07-26) |
| Тестов | 307 lib unit + 1 bin + 7 integration = **315 total** (`cargo test --all-targets`); **322 total** (310 lib + 1 bin + 7 integration + 4 synthetic e2e) под `cargo test --features synthetic-samples --all-targets` |
| Clippy warnings | 0 (`cargo clippy --all-targets --all-features`) |
| Build (dev + release) | ✓ |
| CI | ⛔ отключён — проект локальный, GitHub Actions удалён (2026-07-27); все 4 gate'а (`build`/`test`/`clippy -D warnings`/`fmt --check`) обязаны прогоняться локально перед коммитом |
| Deps latest | ✓ (goblin 0.10.7, clap 4.6.4, serde 1.0.229, serde_json 1.0.151, anyhow 1.0.104, log 0.4.33, env_logger 0.11.11) |

> Строки/модули/тесты в этой таблице — актуализировано 2026-07-27 после T/U/V audit remediation (см. раздел 1b для полной коммит-истории E→V). Остальной текст ниже сохранён как исторический след сессии 2026-07-26 и помечен там, где он устарел.

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

**Итог (на 5744974):** Дни 1-5 недельного плана (раздел 5) закрыты целиком; отдельно прошёл audit-driven проход (7 correctness bugs + test-quality sweep + architecture cleanup) поверх них. Тестов: 66 → 111.

---

## 1c. Коммиты E → V (research-gap remediation + audit-driven correctness/quality sweep) ✓

После раздела 1b landed ещё 18 коммитов на `main`, закрывающие практически весь `RESEARCH_GAPS.md` (§0, §1, §7) плюс собственный трёхфазный аудит (T/U/V) поверх них. Один ряд на коммит, актуализировано 2026-07-27.

| Коммит | Что закрыто |
|---|---|
| `42cb238` (E) | `ProtectorFamily` enum-фундамент + class-level gate (entropy / W+X / stripped-IAT / EP-outside-`.text`) + VMP-version строковые маркеры (`ZwProtectVirtualMemory`) + 5 compressor-семейств (UPX/MPRESS/Petite/PECompact/Upack). Закрывает RESEARCH_GAPS §0 "no class-level gate" и roadmap #1/#3. |
| `94f1af8` (F) | 9 vendor byte-table matchers в новом `src/protector_matchers.rs`: Themida/WinLicense, Enigma, Obsidium, Armadillo, ASPack, Code Virtualizer (dispatcher fingerprint `AC 0F B6 C0 FF 24 87`), Denuvo (detect+refuse), BattlEye, Vanguard. Закрывает roadmap #2. |
| `505bfed` (G) | 8 P0 VMP-семантических matcher'ов: `Add`, `Ldd`, `PushImm`/`PushReg`-split, `Popreg`, `Popf`, `Vsetvsp` + ordering-дисциплина в `classify()`. Закрывает roadmap #4 (первая половина). |
| `8bd4805` + `ea49498` (H) | `JunkStripper` peephole pre-pass подключён в `handler_classifier` перед семантической классификацией; fix-up `ea49498` перенацелил regression-тесты на `Popreg` после G. Закрывает roadmap #5 (первая половина). |
| `832ffc4` (I) | Структурный VMP-dispatcher fingerprint (`protector_matchers::has_{mov_indirect_load,xor_reg_imm,add_reg_mem,indirect_jmp_ff4}` + `protector_signals::scan_rx_sections_for_dispatcher`) — детектирует renamed-section VMP (BattlEye BEDaisy, EAC) без литеральных секций. Закрывает roadmap #6. |
| `337a4fb` (J) | Audit-debt sweep: детерминированный version-detector tiebreak (`src/version.rs`, `.rev()` на `max_by` + explicit tie-log), `sanitise_section_name` log-injection санитайзер (`src/pe_loader.rs`, вызывается из `dispatch_table.rs` и `lib.rs`), `saturating_add`/`checked_add` арифметика в `dispatch_table.rs`/`xor_key_analyzer.rs`/`dispatch_extractor_py.rs`. Закрывает все три пункта §"Новые pending-пункты" из раздела 3 (см. ниже). |
| `92c04af` (K) | `register_roles.rs` — pattern-heuristic voter для VIP/VSP/VKEY канонический ролей (dominance-over-runner-up гейт). Закрывает roadmap #7 (первая половина). |
| `5f42752` (L) | +14 семантических matcher'ов: `Mul`/`Imul`/`Div`/`Idiv`, `Shl`/`Shr`/`Shld`/`Shrd`/`Rcl`/`Rcr`, `Lockor`, `VpushCr0`/`VpushCr3`, `Vnop`. |
| `796da51` (M) | `CryptoScheme` enum (`None`/`Placeholder`/`Vmp2Rolling`/`Vmp3PerHandler`) с `for_version()`-диспетчером в `src/decrypt.rs`; `Vmp2Rolling`/`Vmp3PerHandler` — реальные VMP-цепочки из public write-ups (back.engineering, r0da, vxcall). Закрывает roadmap #8. |
| `d320477` (N) | `--features real-samples` харнесс: `tests/samples.rs` + `tests/fixtures/{vmp1,vmp2,vmp30,vmp35,vmp36,non_vmp}/` scaffold; empty-tree-safe (skip, не fail). Закрывает roadmap #9 (real-sample половина). |
| `6a5d768` (P) | Расширенный junk stripper — Groups E/F/G (constant folding, dead-store elimination, backward liveness) + fixed-point итерация в `junk_stripper.rs`/`junk_stripper_folds.rs`/`junk_stripper_effects*.rs`. Закрывает roadmap #5 (вторая половина). |
| `0c10fdd` (Q) | Cross-handler consistency-гейт для `register_roles` (`register_roles_consistency.rs`) + VMP 3.x суб-версийные hints (`VmpVersionDetail`). Закрывает roadmap #7 (вторая половина). |
| `59908c6` (O) | Дозакрывает семантический классификатор до **35/35** таксономии: `Ret`/`Vemit`/`Popstk`/`Pushstk` + уточнение `Popf`/`Vsetvsp` (см. §Q2 ниже). |
| `b1c3ccd` (R) | `--export-analysis <FILE>` — единый JSON-отчёт (family + version + confidence + dispatch + register roles + handler classifications + crypto scheme + coverage %); `vmp_semantic_confidence: u8` добавлено на `HandlerClassification` (breaking). |
| `8932073` (S) | `src/synthetic_sample.rs` + `src/synthetic_sample_handlers.rs` — генератор VMP-shaped synthetic PE (корректный layout секций, entry stub, dispatcher fingerprint, 256-entry dispatch table, 30 handler shells); `tests/synthetic.rs` — 4 e2e теста под `--features synthetic-samples`, валидирующие весь пайплайн структурно без реальных сэмплов. Закрывает roadmap #9 (synthetic половина). |
| `738bbf9` (T) | Correctness-sweep по итогам живого аудита: log-injection в `protector_signals.rs:138` (пропущенный call site из I), `has_xor_reg_imm` расширен с imm8-only до imm32 + reg-reg XOR форм, инвертированный confidence-scoring для `Ret`/`Vemit`/`Popstk`/`Pushstk` исправлен, `handler_agreement`-денаминатор теперь считает только voting-handlers, `Vsetvsp`-shape документирован как unreachable-on-live-handlers. |
| `267607b` (U) | Test-quality sweep: убраны 2 тавтологичных detector-теста, дубликат `junk_stripper`-теста удалён, ужесточён `FROZEN_ESSENTIALS`-floor в synthetic-harness. |
| `a4e135b` (V) | Architecture-debt sweep: удалены `ProtectorFamily::ExeCryptor`/`SafEngine` (ни разу не эмитили правил), `pub fn family_key` (тонкая обёртка над `as_str`), crate-root re-export'ы `VmpVersionDetail`/`HandlerCounts` (теперь internal-only). |

**Итог (E→V):** RESEARCH_GAPS.md roadmap #1-#9 закрыты (кроме real-sample validation, которая по определению требует user-provided бинарников); §Q2 доведён до 35/35; три "новые pending-пункты" из раздела 3 закрыты J; собственный T/U/V аудит нашёл и исправил 5 correctness-багов + 3 test-quality issues + 3 dead-API removals поверх этого. Тестов: 111 → 315 (322 под `--features synthetic-samples`). Строк: 4 829 → 14 102. Файлов: 13 → 39.

---

## 2. Что осталось (нельзя быстро — нужен реверс / образцы / архитектурное время)

Здесь приоритет: 🔴 critical · 🟠 high · 🟡 medium · ⚪ nice-to-have.

C1, C3, C4, S7, X1, Q6, Q7, Q9, Q10, Q11 закрыты — см. раздел 1a. Ниже — то, что реально осталось.

### ✅ Q2 — Расширить `HandlerClassifier` (multi-byte fingerprints) — ЗАКРЫТО (`06ae816` → `505bfed` G → `5f42752` L → `59908c6` O)

**Где:** `src/handler_classifier.rs::analyze_bytecode`, `src/handler_semantic.rs` (новый модуль).

**Что сделано (`06ae816`):**
- `enum VmpSemantic` в `src/handler_semantic.rs` — ~35 вариантов (Pop, Popstk, Push, Pushstk, Pushreg, Popreg, Ldd, Str, Vsetvsp, Add, Div, Idiv, Mul, Imul, Nand, Nor, Shl/Shr/Shld/Shrd/Rcl/Rcr, Popf, Rdtsc, Cpuid, Vjmp, Vmexit, …).
- `struct SemanticMatcher` с multi-instruction matcher для 8 самых distinctive fingerprints: `Rdtsc`, `Cpuid`, `Vmexit`, `Nand`, `Nor`, `Push`, `Pop`, `Vjmp`.
- Поле `vmp_semantic: Option<VmpSemantic>` на `HandlerClassification` — `#[serde(default)]`, add-only, не ломает существующий `handler_type: String`.
- 20+ юнит-тестов на синтетических handler-body в `src/handler_semantic_tests.rs`.
- Тесты дополнительно ужесточены в `e5fa959` — `assert_eq!(_, None)` вместо `assert_ne!(_, Some(X))` там, где раньше мисклассификация могла тихо проходить.

**Что закрыто дальше (`505bfed` G, `5f42752` L, `59908c6` O):** таксономия доведена до **35/35** — каждый вариант `VmpSemantic` из таблицы ниже либо (a) имеет свой matcher, подключённый к `classify()` (~30 вариантов reachable через реальный порядок вызовов — см. `src/handler_semantic.rs` doc-comment на модуле для полного списка P0-заблокированных byte-identical пар), либо (b) документированный sentinel-only вариант: `Str` затенён (shadowed) `Ldd`'ом — обе формы byte-identical, `Ldd` идёт первым в `classify()` и выигрывает всегда, `Str` — future-extension slot, verified напрямую через свой matcher fn в тестах, но не через `classify()`; `Vexec` статически неотличим от `Vemit` (тот же "jump to VIP-derived address, no table lookup" shape) и folded в него; `Vunk`/`Unknown` — зарезервированные catch-all-варианты, не отдельные matcher-фингерпринты по дизайну.

**Что осталось:**
- True-positive rate на реальных VMP 3.x бинарниках не верифицирован — структурная корректность (byte-shape) подтверждена synthetic-harness'ом (Commit S), но корректность *значений* декодированных операндов и ALU-цепочек всё ещё требует real-sample validation set (Дни 6-7 в разделе 5, всё ещё открыт).
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
3. ✅ Реализовать multi-instruction matcher для всей таксономии — исходно **8 из 10**, доведено до **35/35** через `505bfed` (G, +8 P0), `5f42752` (L, +14), `59908c6` (O, closes remaining Ret/Vemit/Popstk/Pushstk + Popf/Vsetvsp refinement).
4. Fallback на существующие x86-instruction-level labels для неопознанных handlers — не требовалось отдельной реализации, `handler_type: String` уже был fallback по дизайну поля #2.
5. ✅ Unit-тесты на синтетических handler-body последовательностях — 20+ тестов в `src/handler_semantic_tests.rs`.

**Что НЕЛЬЗЯ верифицировать без sample-а:** true-positive rate на реальных VMP 3.x бинарниках. Структурная корректность (все 35 matcher-shapes согласуются друг с другом и с остальным пайплайном) теперь проверяется synthetic-sample harness'ом (Commit S, `--features synthetic-samples`) без реальных бинарников; корректность декодированных *значений* операндов всё ещё требует real-sample validation set (~5-10 разных VMP-protected `.exe`) — открытый пункт, см. раздел 5 (Дни 6-7).

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

### ✅ Спринт 2 (завершён) — «Полное покрытие handlers»
- Q2 — VMP-семантический классификатор: **35/35** taxonomy закрыто. Исходно 8 из ~35 (`06ae816`), затем `505bfed` (G, +8 P0), `5f42752` (L, +14), `59908c6` (O, дозакрывает Ret/Vemit/Popstk/Pushstk + Popf/Vsetvsp refinement). См. §Q2.
- Q4 — exhaustive `decode_operands` под Q2 taxonomy: **не сделано**, API стал breaking (`&mut OpcodeCryptor`) в `64288a4`, но matching всё ещё на старых x86-labels. См. §Q4.
- Q3 — символический ALU decompose: `dummy → "vsp+0"/"vsp+8"` **сделано** `64288a4`; symbolic engine для произвольных цепочек — нет. См. §Q3.

### 🟡 Спринт 4 (частично завершён) — «Полировка»
- Q15 — Rust `unicorn-engine` вместо Python subprocess. Не начато.
- Q14 — command-injection sanity + reproducibility logging. Не начато.
- X-new/A — подключить `OpcodeCryptor` в `Bytecode::decode_operands`. ✅ shipped `64288a4`.
- X-new/B — подключить `ALUReconstructor` в decode-pipeline. ✅ shipped `64288a4` (не дожидались отдельного Q3-символьного движка — использована текущая `decompose_chain`).
- X-new/C — end-to-end валидация на реальном x86 VMP-сэмпле. Не начато — см. раздел 5, Дни 6-7 (по-прежнему заблокировано отсутствием сэмплов).
- X-new/D — rustdoc examples для публичного API. Не начато.

### ✅ Новые pending-пункты, найденные аудитом — ЗАКРЫТО в `337a4fb` (J)

- **Version-detector tiebreaker** (`src/version.rs`) — ✅ закрыто. `max_by` теперь итерирует в обратном порядке (`.rev()`) так, что среди равных максимумов побеждает первый элемент исходного `candidates`-массива (детерминированно, а не по умолчанию "последний из равных"); tie explicitly логируется через `log::warn!` с указанием, какие кандидаты были отброшены только порядком массива. См. `src/version.rs` — поиск `tiebreak` в doc-комментарии над вызовом `max_by`.
- **Log-injection через section-имена** — ✅ закрыто. `sanitise_section_name` (`src/pe_loader.rs:256`) экранирует control/ESC/non-ASCII байты перед логированием; вызывается из `dispatch_table.rs:145` и `lib.rs:189`. Третий call site — `src/protector_signals.rs:138` (добавлен структурным dispatcher-сканером `I`, не наследовал санитизацию) — закрыт отдельно в Commit T (`738bbf9`).
- **Unchecked `image_base + rva` арифметика** — ✅ закрыто. `saturating_add`/`checked_add` sweep применён по всем точкам сложения в `src/dispatch_table.rs`, `src/xor_key_analyzer.rs`, `src/dispatch_extractor_py.rs` (21 occurrence суммарно по проекту на момент 2026-07-27 — `grep -rn saturating_add src/`).

---

## 5. Недельный roadmap для следующей сессии (реалистичный)

> **Дни 1-5 закрыты** (коммиты `b95246d`, `06ae816`, `64288a4` — см. раздел 1b для детального разбора того, что именно сделано против того, что планировалось). Таблица ниже сохранена как исходный план сессии 2026-07-26; актуальный статус — колонка "Факт" справа. **Дни 6-7 частично открыты** (актуализировано после Commits N/S, см. §1c): структурная валидация всего детекционного пайплайна (family + version + dispatch table + register roles + semantic classifier согласуются друг с другом) теперь покрыта `--features synthetic-samples` (Commit S, `8932073`) — 4 e2e-теста прогоняют CLI против сгенерированных VMP-shaped PE и проверяют `--export-analysis` JSON. Real-sample валидация (`--features real-samples`, Commit N, `d320477`) по-прежнему ждёт user-provided VMP-бинарников в `tests/fixtures/vmp*/` — пустое дерево тестов проходит "skip", а не "fail", но ничего не *доказывает*. Семантическая валидация Дней 6-7 (корректность значений decrypted operands, корректность ALU-цепочек на реальном коде) остаётся открытой — synthetic-генератор кодирует byte-shapes, которые сам же классификатор ожидает, так что он не может обнаружить расхождение с реальным VMP-выхлопом.

Цель: получить рабочий инструмент, честно анализирующий простой VMP-3 sample (hello world под VMP), с выхлопом узнаваемых handler-имён.

| День | Задача | Как делать | Оценка | Зависимости | Факт |
|---|---|---|---|---|---|
| **1** | F1+F2+F3 — CLI полировка | 1 subagent (мелкий, ~30 мин фоном): дефолт VIP из entry_point, graceful exit на non-VMP, `--force-version`. Плюс: интеграционный тест который запускает бинарь через `assert_cmd` на mock-PE fixture (ловит будущие CLI-регрессии как `-v` collision). | 2 ч | — | ✅ `b95246d` |
| **2** | Q2-lite — VmpSemantic enum + 6 базовых matchers | 1 subagent: `VmpSemantic { Pop, PushImm, PushReg, Nand, Nor, Ret, Vmexit, Vjmp, Unknown }`, `HandlerClassification.vmp_semantic: Option<VmpSemantic>`, multi-instruction matcher для этих 6 (VSP-fetch → operand → CTX-store etc). Fallback на существующие x86-labels. Тесты на синтетических handler-body. | 4-6 ч | Taxonomy §Q2 | ✅ `06ae816` (8 matchers вместо 6, другой набор — см. §Q2) |
| **3** | Q2-full — оставшиеся ~29 handlers + Q4 (`decode_operands` refresh) | 1 subagent: расширяем matcher-таблицу до полной taxonomy; обновляем `decode_operands` под новые VmpSemantic. | 6-8 ч | День 2 | 🟡 не сделано — только API-breaking смена сигнатуры `decode_operands` в `64288a4`, matcher-таблица не расширена |
| **4** | X-new/A — подключить `OpcodeCryptor` в pipeline | Пишу сам (не subagent): в `decode_operands` вызвать `OpcodeCryptor::decrypt_operands` для VMP-версий которые шифруют immediate. CRC-init из VIP handler-а. Тесты. | 4 ч | Q2 | ✅ `64288a4` |
| **5** | Q3 — символический ALU decompose | 1 subagent: `VspSlot(offset)` вместо dummy строк; De Morgan → синтезированный `Add/Sub/And/Or/Xor`; вызов из `decode_operands` для NOR/NAND. Тесты. | 6-8 ч | Q2 | ✅ частично `64288a4`+`e586638` (строковые слоты, не typed `VspSlot`; см. §Q3) |
| **6** | X-new/C — real-sample validation | Собираю 3-5 VMP-3 sample-бинарников (можно с VMProtect Free/Trial на простом hello-world). Прогоняю CLI. Ловим bugs. Правлю. | 6 ч | Дни 1-5 | 🟡 ЧАСТИЧНО — structural pipeline validation закрыт synthetic-harness'ом без реальных бинарников (`8932073` S); real-sample-половина (`d320477` N харнесс существует, `tests/fixtures/vmp*/` по-прежнему пусты) всё ещё ждёт user-provided сэмплов |
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
- Коммиты на `main` (research-gap remediation + T/U/V audit, см. раздел 1c для деталей):
  - `42cb238` — E: `ProtectorFamily` foundation + class-level gate + VMP string markers
  - `94f1af8` — F: vendor byte-table matchers (Themida/Enigma/Obsidium/Armadillo/ASPack/CV/Denuvo/BattlEye/Vanguard)
  - `505bfed` — G: 8 P0 VMP semantic matchers
  - `8bd4805` / `ea49498` — H: junk-code stripper pre-pass + fix-up
  - `832ffc4` — I: structural VMP dispatcher fingerprint (renamed-section detection)
  - `337a4fb` — J: audit-debt sweep (version tiebreak + log sanitisation + saturating arithmetic)
  - `92c04af` — K: register-role canonicaliser
  - `5f42752` — L: +14 semantic matchers (arithmetic/shift/rotate/system)
  - `796da51` — M: `CryptoScheme` per-version dispatch
  - `d320477` — N: real-sample harness (`--features real-samples`)
  - `6a5d768` — P: enhanced junk stripper (Groups E/F/G) + fixed-point loop
  - `0c10fdd` — Q: register-role cross-handler consistency + VMP sub-version hints
  - `59908c6` — O: semantic classifier complete (35/35)
  - `b1c3ccd` — R: `--export-analysis` unified JSON + confidence scoring
  - `8932073` — S: synthetic-sample generator + `--features synthetic-samples` E2E harness
  - `738bbf9` — T: correctness sweep (5 fixes) from post-implementation audit
  - `267607b` — U: test-quality sweep from post-implementation audit
  - `a4e135b` — V: architecture-debt sweep from post-implementation audit
- Auto memory (для будущих сессий): `C:\Users\Platon\.claude\projects\D--GitHub-Rust-Projects-VM-Protect-Research\memory\`.
- Reference sources для Q2 (GPL-3.0, READ ONLY): `0xnobody/vmpattack`, `can1357/NoVmp`.

---

*Отчёт впервые собран Claude Code (Opus 4.7) в рамках сессии 46b758ca на 2026-07-26 — актуализирован после live-запуска CLI на не-VMP бинарнике, добавлен реалистичный недельный план для следующей сессии. Ревизия 2026-07-27 (Commit D, docs sync): сверены 6 дополнительных коммитов, закрывших Дни 1-5 недельного плана плюс отдельный audit-driven проход (Commits A-C — 7 correctness fixes, test-quality sweep, architecture cleanup). Ревизия 2026-07-27 (Commit W, docs sync после T/U/V): сверены 18 дополнительных коммитов E→V, закрывающих практически весь `RESEARCH_GAPS.md` roadmap (класс-левел gate, 9 vendor matchers, 35/35 semantic taxonomy, junk stripper, register-role canonicaliser, per-version crypto, real+synthetic sample harnesses, unified JSON export) плюс собственный T/U/V аудит (5 correctness fixes, 3 test-quality fixes, 3 dead-API removals). Строки/модули/тесты в разделе 0 пересчитаны напрямую (`wc -l`, `cargo test --all-targets`, `cargo test --features synthetic-samples --all-targets`), не оценены.*
