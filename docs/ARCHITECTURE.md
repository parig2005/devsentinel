# DevSentinel — Architecture Notes

Companion to the README. This file explains *why* the system is shaped the way
it is, which is what gets asked about in a viva.

## Request lifecycle

```
Browser
  |  POST /analyze  (multipart/form-data)
  v
HomeController.analyze()
  |  catches AnalysisException -> redirect home with flash message
  v
UploadValidator.validate()          extension, size, filename safety
UploadValidator.validateContent()   NUL-byte scan, Java type declaration
  v
AnalysisService.analyse()
  |
  +--> JavaParser.parse()                      AST, or JavaParseException
  |
  +--> StaticRuleEngine.analyse(cu)            8 rules, no network. ALWAYS runs.
  |
  +--> StaticRuleEngine.extractMethodSnippets(cu)
  |        |
  |        v
  |    AiAnalysisClient.predictAll()           bounded concurrency = 4
  |        |  flatMapSequential preserves order
  |        |  onErrorResume -> offlineFallback()   <-- never throws
  |        v
  |    Python FastAPI /api/v1/predict
  |        signature match -> CodeBERT embed -> cosine similarity
  |
  +--> mergeFindings()                         dedupe, attribute, sort
  |
  +--> applySummaryCounts()                    counts + weighted risk score
  |
  +--> AnalysisRecordRepository.save()         cascades to findings
  v
redirect:/results/{id}  ->  Thymeleaf results.html
```

## Why the AI call cannot break the analysis

This is deliberate, layered defence:

1. **`WebClientConfig`** sets a 3 s connect timeout and a 20 s response timeout,
   plus Netty read/write timeout handlers. A hung service cannot block forever.
2. **`AiAnalysisClient.predict()`** ends every reactive chain with
   `.onErrorResume(...)` returning `AiPredictResponse.offlineFallback()`. The
   returned `Mono` emits a value on every path — it has no error signal.
3. **`predictAll()`** has a second safety net: `onErrorReturn` plus a
   `blockOptional(...).orElseGet(...)` that manufactures one fallback per
   snippet.
4. **`AnalysisService`** inspects the responses. If every one is a fallback, the
   run is `DEGRADED`; static findings are already in hand regardless.

The ordering matters: static rules run **before** the AI call and never depend
on its result. That is the whole reason degraded mode produces useful output
rather than an empty report.

## Why `mergeFindings` exists

Without it, a file with concatenated SQL produces two findings for one bug —
one from the JVM rule engine, one from the Python signature engine. That looks
broken to anyone reading the report.

The merge rule: same `vulnerabilityType`, and the static finding's line number
falls inside the AI-scored method's line range, means they are the same issue.
Keep the static line number (exact, from the AST) and the AI confidence (more
informative than a fixed rule constant). Tag it `STATIC+AI`.

An AI finding with no static counterpart is kept separately — that is the AI
layer earning its place, e.g. `NULL_POINTER_RISK`, which has no JVM-side rule.

## Why a shared vulnerability catalog

`VulnerabilityCatalog` is the single source of truth for display name, severity
band, category, and OWASP mapping. Both the static rules and the AI-result
mapper read from it.

Without it, the Python service could report a severity of 9.0 for SQL injection
while the Java rule called it `CRITICAL` on a different scale, and the UI would
show inconsistent values for the same bug class. `VulnerabilityCatalogTest`
asserts every type the Python engine can emit is registered here, so a
mismatch fails the build instead of silently rendering "Unclassified Issue".

## Concurrency

`predictAll` uses `flatMapSequential(this::predict, 4)`:

- **Bounded at 4** because the Python service is a single Uvicorn worker holding
  one model in memory. Unbounded parallelism would queue requests internally and
  blow past the timeout.
- **Sequential, not plain `flatMap`**, because `AnalysisService` pairs
  `aiResponses.get(i)` with `snippets.get(i)`. Plain `flatMap` interleaves
  completions and would misattribute findings to the wrong methods.

## Threading note

`AnalysisService` calls `.blockOptional()` on the reactive chain. That is
correct here: this is a servlet application, the controller thread is already
dedicated to the request, and the work must finish before the response renders.
The reactive layer buys concurrency *within* one analysis (4 snippets in flight
at once), not an end-to-end non-blocking stack.

`JavaParser` is instantiated per call rather than using `StaticJavaParser`,
which is global mutable state and not safe across concurrent uploads.

## Persistence design

Two tables rather than four. An earlier design separated users, files, reports,
and details. Authentication was dropped from scope, which removed the users
table, and separating "file" from "report" added a join without adding
information — one upload produces exactly one report in this system.

`AnalysisRecord.findings` is `FetchType.EAGER` because the results page always
needs them and `spring.jpa.open-in-view=false` means lazy loading outside the
service layer would throw.

The back-reference `VulnerabilityFinding.analysisRecord` carries three
exclusions, all necessary:

| Annotation | Prevents |
|---|---|
| `@EqualsAndHashCode.Exclude` | `StackOverflowError` from Lombok's generated `equals` |
| `@ToString.Exclude` | the same recursion in `toString` |
| `@JsonIgnore` | an infinite JSON document from `ApiController` |

## Error handling boundaries

| Layer | Catches | Result |
|---|---|---|
| `HomeController.analyze` | `AnalysisException`, `IOException` | redirect home + flash message |
| `GlobalExceptionHandler` | `MaxUploadSizeExceededException` | 413 / friendly message |
| `GlobalExceptionHandler` | `NoResourceFoundException` | plain 404 (not a redirect) |
| `GlobalExceptionHandler` | `Exception` | logged server-side, generic message to user |

`/api/**` requests get JSON from the same handler; browser requests get a
redirect. `server.error.include-stacktrace=never` guarantees no stack trace
reaches the browser.

## What was deliberately left out

- **Authentication** — out of scope; the brief called for a focused project
- **Docker** — adds a moving part without helping a single-laptop demo
- **Message queue** — unnecessary below roughly a hundred concurrent uploads
- **React** — a build pipeline that would not improve the analysis engine
- **Microservices beyond the two** — the split exists for a technical reason
  (JVM parsing vs Python ML), not because more services are better
