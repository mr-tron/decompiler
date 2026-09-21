# Техническое задание: декомпилятор TVM/Fift ASM → FunC

## 1. Цель

Разработать HTTP-сервис, принимающий скомпилированный TVM-код контракта в base64 и автоматически:

1. декодирующий входные данные;
2. дизассемблирующий код штатными инструментами TON;
3. анализирующий полученный Fift/TVM ASM;
4. определяющий наиболее вероятную версию компилятора FunC;
5. определяющий наиболее вероятные параметры/flags компиляции;
6. восстанавливающий компилируемый исходный код на FunC;
7. автоматически проверяющий результат повторной компиляцией;
8. возвращающий FunC-код, предполагаемую версию компилятора, flags и оценку качества декомпиляции.

Главный практический критерий качества:

> Полученный FunC должен по возможности успешно компилироваться обратно в код, максимально близкий к исходному.

Точное восстановление оригинального текста исходника не требуется.

Если возможно получить exact round-trip до исходного code cell/hash — это максимальный уровень уверенности.

---

# 2. Исходные данные

В репозитории/рабочем окружении будет предоставлена директория:

`orig_func_verified/`

В ней находится около 300 проверенных исходных FunC-контрактов.

Для этих контрактов известны либо должны быть доступны метаданные:

* исходный `.fc`;
* фактическая версия `func`, которой был собран контракт;
* фактические compiler flags;
* при наличии — ожидаемый code hash / BOC / compiled code.

Если формат директории отличается от ожидаемого, агент должен самостоятельно исследовать структуру и написать loader/adaptor.

Не изменять содержимое `orig_func_verified`.

Эти 300 контрактов считать одновременно:

* seed corpus;
* regression corpus;
* источником реальных FunC-паттернов;
* материалом для автоматической генерации дополнительных compiler experiments.

---

# 3. Важное требование: версия компилятора неизвестна на входе

Production API НЕ получает версию FunC-компилятора.

Декомпилятор должен самостоятельно определить:

* наиболее вероятную версию `func`;
* при невозможности точного определения — диапазон/набор совместимых версий;
* наиболее вероятные compiler flags.

Версия и flags являются частью результата декомпиляции, а не обязательными входными параметрами.

Необходимо экспериментально исследовать, насколько реально их определять по generated ASM/code.

---

# 4. Research / bootstrap stage

Перед реализацией окончательной логики декомпиляции провести автоматизированное исследование компилятора FunC.

## 4.1. Compiler matrix

Собрать контракты из `orig_func_verified` различными релевантными версиями `func`.

Использовать несколько исторических версий компилятора, покрывающих версии, которыми могли быть собраны реальные контракты.

Для каждой версии проверить релевантные combinations compiler flags.

Получить dataset вида:

`FunC source × compiler version × flags → compiled TVM code → Fift/TVM ASM`

Сохранять результаты в reproducible cache/database, чтобы не перекомпилировать весь corpus при каждом запуске.

Compiler binaries/toolchains должны быть version-pinned и воспроизводимы.

## 4.2. Differential analysis

Автоматически сравнить результаты компиляции одного FunC-кода:

* между версиями `func`;
* между compiler flags;
* между optimizer settings.

Найти характерные различия:

* instruction selection;
* ordering;
* generated continuations;
* conditional lowering;
* constant folding;
* tuple operations;
* stack manipulation;
* calls;
* inlining;
* method layout;
* optimizer-specific sequences;
* другие устойчивые compiler fingerprints.

Не предполагать заранее, что версия определяется одной сигнатурой.

Проверить это экспериментально.

## 4.3. Compiler fingerprinting

Построить механизм оценки:

`P(compiler version, flags | observed code/ASM)`

Не обязательно использовать ML.

Предпочтительно начать с интерпретируемой системы:

* fingerprints;
* pattern matching;
* likelihood/score;
* исключение несовместимых версий;
* сравнительная recompilation.

Если несколько версий генерируют идентичный код для данного контракта, вернуть их как совместимые, выбрав наиболее вероятную версию только при наличии оснований.

Не заявлять ложную точность.

---

# 5. Генерация дополнительного corpus

300 контрактами не ограничиваться.

На основании конструкций, найденных в `orig_func_verified`, автоматически генерировать минимальные FunC-программы / microprograms для изучения lowering.

Примеры исследуемых конструкций:

* arithmetic;
* comparisons;
* boolean expressions;
* if / ifnot;
* nested conditions;
* loops;
* function calls;
* inline / inline_ref;
* tuples;
* destructuring;
* slices;
* cells;
* builders;
* dictionaries;
* continuations;
* exceptions;
* method IDs;
* impure operations;
* stack-sensitive expressions;
* constant expressions;
* return variants;
* combinations перечисленных конструкций.

Компилировать microprograms разными версиями и flags.

Цель — получить значительно больше локальных соответствий:

`FunC AST/pattern → generated TVM pattern`

и обратных:

`TVM pattern → candidate FunC AST patterns`.

---

# 6. Архитектура декомпилятора

Не строить основной decompiler как LLM prompt `ASM → FunC text`.

Основной pipeline должен быть детерминированным и тестируемым.

Рекомендуемая архитектура:

`BOC/base64`
→ `TON disassembler`
→ `normalized ASM`
→ `ASM parser`
→ `CFG`
→ `symbolic stack analysis`
→ `IR`
→ `structured IR`
→ `FunC AST`
→ `FunC source`
→ `recompile`
→ `compare`
→ `rewrite/search`
→ `final result`

Допускается изменить внутреннюю архитектуру, если эксперименты покажут более надежный вариант.

---

# 7. ASM parser

Поддерживать стандартный вывод штатного дизассемблера TON monorepo.

Парсер не должен быть набором regex над полным текстом.

Построить нормализованное внутреннее представление инструкций.

Для каждой инструкции по возможности иметь:

* opcode/type;
* operands;
* stack effect;
* control-flow effect;
* references/cells;
* source textual representation.

Неизвестная инструкция не должна приводить к silent corruption.

Она должна либо:

* поддерживаться conservative fallback-механизмом;
* либо снижать confidence;
* либо приводить к явной ошибке unsupported instruction.

---

# 8. Symbolic stack IR

Это ключевая часть реализации.

Не пытаться непосредственно преобразовывать последовательности стековых инструкций в строки FunC.

Выполнять symbolic stack execution.

Например условная последовательность:

`PUSH a`
`PUSH b`
`ADD`

должна превращаться во внутреннее выражение примерно:

`t0 = add(a, b)`

Использовать SSA-like representation или другое подходящее IR.

IR должен позволять:

* отслеживать происхождение stack values;
* объединять значения на CFG merge;
* распознавать expressions;
* восстанавливать function arguments;
* восстанавливать return values;
* отслеживать side effects;
* различать pure/impure operations.

---

# 9. Control Flow Graph

Построить CFG.

Определять:

* basic blocks;
* branches;
* joins;
* continuations;
* loops;
* terminal blocks;
* function boundaries, насколько это возможно.

После CFG выполнять control-flow structuring:

* if;
* if/else;
* loops;
* early return;
* nested constructs;
* continuation-related FunC patterns.

Если несколько FunC-конструкций соответствуют одному CFG, хранить alternatives до стадии recompilation/search.

---

# 10. FunC AST

Результат структурного анализа должен сначала представляться как FunC AST/IR, а не текст.

AST должен поддерживать как минимум:

* functions;
* arguments;
* local variables;
* literals;
* calls;
* operators;
* tuple expressions;
* assignments;
* conditions;
* loops;
* returns;
* relevant FunC attributes/specifiers.

Pretty-printer является отдельным последним этапом.

Все rewrite/search transformations должны работать преимущественно над AST/IR, а не regex-заменами исходного FunC.

---

# 11. Recompilation oracle

Компилятор FunC использовать как oracle.

После первоначальной декомпиляции автоматически пробовать candidate:

`candidate.fc`
→ `func(candidate version, candidate flags)`
→ `compiled candidate`
→ `disassemble`
→ `normalized comparison`

Сравнивать с оригиналом на нескольких уровнях.

### Level 1 — exact code hash

Если:

`candidate_code_hash == original_code_hash`

результат считать exact round-trip.

### Level 2 — exact normalized ASM

Если ASM совпадает после только безопасной нормализации — очень высокая уверенность.

### Level 3 — structural match

Сравнивать:

* CFG;
* basic blocks;
* opcode sequences;
* constants;
* calls;
* stack effects;
* cell/reference structure.

### Level 4 — partial reconstruction

Если код компилируется, но значительная часть структуры отличается, вернуть результат только с соответствующим confidence и diagnostics.

---

# 12. Search / rewrite loop

При несовпадении initial candidate с исходным кодом автоматически пытаться улучшить результат.

Pipeline:

`candidate AST`
→ compile
→ structural diff
→ locate mismatching region
→ generate alternative equivalent AST fragments
→ compile alternatives
→ compare
→ retain best candidate
→ repeat

Примеры альтернатив:

* expression ordering;
* temporary variable vs inline expression;
* alternative conditional form;
* tuple destructuring form;
* inline/inlining-related forms;
* alternative return construction;
* equivalent FunC operators/functions;
* optimizer-sensitive source forms.

Ограничить search:

* временем;
* количеством candidates;
* depth;
* отсутствием улучшения.

Сервис не должен зависать на сложном контракте.

---

# 13. Confidence model

API должен возвращать не просто произвольное число, а объяснимую оценку.

Предлагаемая шкала:

`exact`
— recompilation дала тот же code hash.

`very_high`
— exact normalized instruction/cell representation, но hash по технической причине нельзя подтвердить.

`high`
— практически полный structural match, незначительные различия.

`medium`
— FunC успешно компилируется, большая часть CFG/instructions соответствует исходнику.

`low`
— получен компилируемый FunC, но соответствие подтверждено недостаточно.

`failed`
— корректную декомпиляцию получить не удалось.

Дополнительно вернуть числовой:

`confidence: 0.0 .. 1.0`

Но число должно вычисляться из измеримых признаков, например:

* hash match;
* instruction match;
* CFG match;
* percentage unsupported instructions;
* stack-analysis certainty;
* compiler fingerprint certainty;
* recompilation success.

---

# 14. HTTP API

Минимальный endpoint:

`POST /v1/decompile`

Request:

```json
{
  "code": "<base64>"
}
```

Опционально разрешить:

```json
{
  "code": "<base64>",
  "max_search_time_ms": 10000
}
```

Не позволять клиенту задавать произвольные executable/compiler paths или shell arguments.

Successful response:

```json
{
  "success": true,
  "func": "... reconstructed FunC source ...",
  "compiler": {
    "version": "0.x.x",
    "confidence": 0.91,
    "compatible_versions": [
      "0.x.x",
      "0.x.y"
    ],
    "flags": [
      "..."
    ]
  },
  "decompilation": {
    "confidence": 0.94,
    "quality": "high",
    "recompiles": true,
    "exact_hash_match": false,
    "instruction_match": 0.987,
    "cfg_match": 1.0,
    "unsupported_instructions": []
  },
  "diagnostics": []
}
```

Exact result:

```json
{
  "success": true,
  "func": "...",
  "compiler": {
    "version": "...",
    "confidence": 1.0,
    "compatible_versions": ["..."],
    "flags": ["..."]
  },
  "decompilation": {
    "confidence": 1.0,
    "quality": "exact",
    "recompiles": true,
    "exact_hash_match": true,
    "instruction_match": 1.0,
    "cfg_match": 1.0,
    "unsupported_instructions": []
  },
  "diagnostics": []
}
```

Failure:

```json
{
  "success": false,
  "error": {
    "code": "DECOMPILATION_FAILED",
    "message": "...",
    "stage": "stack_analysis"
  },
  "diagnostics": []
}
```

Использовать подходящие HTTP status codes для malformed base64, invalid BOC, internal errors и т.д.

---

# 15. Debug API / CLI

Кроме production API сделать CLI для разработки:

`decompiler decompile contract.boc`

`decompiler disasm contract.boc`

`decompiler detect-compiler contract.boc`

`decompiler verify contract.boc candidate.fc`

`decompiler corpus build ./orig_func_verified`

`decompiler corpus evaluate ./orig_func_verified`

`decompiler compiler-diff <source.fc>`

CLI должен позволять разработчику видеть:

* normalized ASM;
* CFG;
* symbolic stack;
* IR;
* generated FunC AST;
* compiler candidates;
* ASM diff;
* причины потери confidence.

---

# 16. Evaluation

Обязательно сделать автоматический benchmark.

Важно избежать data leakage.

Разделить исходные контракты минимум на:

* development/train corpus;
* validation corpus;
* final holdout corpus.

Holdout не использовать для ручной подгонки rewrite rules.

Для каждого контракта измерять:

1. disassembly success;
2. parser success;
3. CFG reconstruction success;
4. FunC generation success;
5. FunC recompilation success;
6. exact code/hash match;
7. exact/normalized ASM match;
8. instruction similarity;
9. CFG similarity;
10. compiler-version detection accuracy;
11. compiler-flags detection accuracy;
12. runtime;
13. search candidate count.

Формировать итоговый отчет.

Например:

```text
contracts                         300
parsed                          98.7%
generated FunC                  94.3%
recompiled                      91.0%
structural match >= 0.95        82.0%
exact ASM                       63.0%
exact code hash                 51.0%

compiler exact version          74.0%
compiler compatible family      93.0%
flags exact                     81.0%

median time                     ...
p95 time                        ...
```

Цифры здесь только пример формата, не target.

Не оптимизировать benchmark путем специальных правил, содержащих hashes/имена конкретных holdout-контрактов.

---

# 17. Анализ ошибок

После каждого существенного этапа разработки автоматически кластеризовать failures.

Например:

```text
control-flow reconstruction
tuple reconstruction
unknown opcode
continuation handling
compiler version ambiguity
optimizer ambiguity
expression ordering
inline mismatch
cell/reference mismatch
...
```

Приоритет разработки определять по количеству реальных failures.

Не добавлять сотни ad-hoc правил до измерения их влияния на corpus.

---

# 18. Требования к generated FunC

Generated code должен быть:

1. синтаксически валидным;
2. компилироваться выбранной версией `func`, если response сообщает `recompiles=true`;
3. быть относительно читаемым;
4. использовать стабильные autogenerated names там, где оригинальные имена восстановить невозможно.

Например:

`arg0`, `arg1`

`v0`, `v1`

`tmp0`

Не пытаться выдумывать оригинальные имена переменных.

Не выдавать комментарии вроде:

`// probably owner_address`

если это нельзя вывести из кода.

Можно добавлять технические комментарии только там, где reconstruction incomplete, если они не мешают компиляции.

---

# 19. Безопасность исполнения compiler toolchain

Поскольку сервис обрабатывает недоверенный binary input и запускает tooling:

* не выполнять входные данные как shell;
* subprocess запускать без shell interpolation;
* compiler/disassembler запускать с timeout;
* ограничить размер input;
* ограничить memory/CPU;
* ограничить количество search/recompile attempts;
* использовать временные sandbox directories;
* очищать temporary files;
* не позволять входу управлять filesystem paths;
* желательно изолировать compiler workers контейнером/process sandbox.

Production endpoint должен быть устойчив к намеренно патологическим BOC/code cells.

---

# 20. Кэширование

Кэшировать дорогостоящие операции:

* disassembly;
* compiler fingerprint;
* candidate compilation;
* normalized ASM;
* structural comparison.

Ключ compilation cache должен включать минимум:

`hash(source AST/source text + compiler binary identity + flags)`.

Нельзя считать строку версии достаточной идентичностью compiler binary.

---

# 21. Reproducibility

Зафиксировать:

* TON toolchain revisions;
* `func` binaries/revisions;
* compiler hashes;
* supported flags;
* environment;
* corpus-generation configuration.

Команда bootstrap должна позволять на чистой машине воспроизвести compiler matrix.

---

# 22. Что НЕ делать

Не строить систему исключительно как:

`ASM → LLM → FunC`.

Не считать красивый FunC успешной декомпиляцией без recompilation.

Не считать совпадение нескольких инструкций доказательством compiler version.

Не hardcode'ить результаты конкретных контрактов.

Не использовать code hash как единственный сигнал поиска: hash дает только exact/non-exact результат.

Не смешивать semantic reconstruction, compiler fingerprinting и pretty-printing в одном модуле.

Не скрывать unsupported ASM за высоким confidence.

---

# 23. Порядок реализации

Работать итеративно.

## Phase 1 — environment

Поднять воспроизводимые версии TON tooling и `func`.

Исследовать `orig_func_verified`.

Сделать deterministic compilation/disassembly harness.

## Phase 2 — corpus research

Скомпилировать corpus различными версиями/flags.

Сделать compiler differential analysis.

Сохранить результаты и отчет о найденных fingerprints.

## Phase 3 — parser + IR

Реализовать:

* ASM parser;
* CFG;
* stack effects;
* symbolic execution;
* базовый IR.

Покрыть тестами реальные инструкции corpus.

## Phase 4 — basic FunC reconstruction

Реализовать FunC AST и восстановление основных expressions/control flow.

Добиться компилируемого результата на простых контрактах.

## Phase 5 — oracle

Добавить автоматическую recompilation и structural comparison.

## Phase 6 — compiler detection

Используя compiler matrix, реализовать version/flags fingerprinting.

Проверить отдельно на holdout.

## Phase 7 — rewrite/search

Использовать compiler oracle для устранения неоднозначностей и приближения generated code к исходному binary.

## Phase 8 — production API

HTTP API, resource limits, caching, structured errors.

## Phase 9 — benchmark

Прогнать полный holdout benchmark.

Сформировать machine-readable JSON и human-readable отчет.

---

# 24. Ключевой принцип разработки

В спорной ситуации не пытаться угадать, как FunC «обычно должен выглядеть».

Проверять гипотезу экспериментально:

1. сформировать минимальный FunC example;
2. скомпилировать интересующими версиями/flags;
3. дизассемблировать;
4. сравнить;
5. превратить наблюдение в generalizable rule;
6. проверить rule на corpus;
7. добавить regression test.

Компилятор является основным oracle системы.

---

# 25. Definition of Done

Проект считается готовым к первой production-версии, когда:

* существует documented `POST /v1/decompile`;
* endpoint принимает TVM compiled code в base64;
* штатный TON tooling используется для disassembly;
* версия `func` не требуется от пользователя;
* сервис самостоятельно оценивает compiler version и flags;
* сервис генерирует FunC;
* generated FunC автоматически проверяется recompilation;
* response содержит confidence и причины снижения confidence;
* malformed/unsupported input дает structured error;
* существует reproducible compiler/corpus harness;
* существует holdout benchmark;
* существуют regression tests;
* compiler versions/toolchains pinned;
* результаты исследования compiler fingerprints сохранены в документации;
* README описывает архитектуру, запуск API, добавление новой версии `func` и запуск benchmark.

## Дополнительный приоритет

Не ставить exact source reconstruction выше robustness.

Приоритеты:

1. не выдавать неверный результат с высокой уверенностью;
2. выдавать компилируемый FunC;
3. сохранять семантику/структуру исходного TVM-кода;
4. максимально приближать recompilation к исходному ASM;
5. получать exact code hash там, где это возможно;
6. readability generated FunC;
7. сходство с оригинальным formatting/naming — практически не важно.
