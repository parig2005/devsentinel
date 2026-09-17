# DevSentinel — Demo & Viva Guide

Everything to run and defend the project, in the order you will need it.

---

## Pre-demo checklist

Do all of this the **day before**, not on the morning of.

- [ ] `java -version` → 17 or newer
- [ ] `mvn -version` → works in a fresh terminal
- [ ] `python --version` → 3.10–3.12
- [ ] `mvn clean install` → BUILD SUCCESS (dependencies cached locally)
- [ ] Python venv created and `pip install -r requirements.txt` finished
- [ ] **CodeBERT already downloaded** — start the AI service once and wait for
      `Model loaded successfully.` Never let a 500 MB download happen on
      college wifi during your slot.
- [ ] `mvn test` → green
- [ ] `pytest tests/ -v` → 28 passed
- [ ] Upload the sample file once end to end and confirm the report renders
- [ ] Delete `data/` for a clean History, or leave a couple of runs in it to
      prove persistence — your choice, but decide beforehand
- [ ] **Record a 3-minute backup video.** Insurance against a dead laptop,
      a broken projector, or no network.

---

## The 6-minute demo script

**Minute 0–1: what and why**

> "DevSentinel finds security vulnerabilities in Java source code. You upload a
> file, it parses it into an abstract syntax tree, applies security rules to
> that tree, and uses a CodeBERT language model to score how confident each
> finding is. Everything is saved to a database."

Have <http://localhost:8080> already open. Point at the green **AI Engine:
ONLINE** banner.

**Minute 1–2: the analysis**

Upload `samples/VulnerableExample.java`, click **Analyse Code**.

Walk through one CRITICAL finding — SQL injection is the best one:

> "It found the injection at line 31, inside `findUserByName`. It tells you the
> OWASP category, shows the exact offending line, explains why concatenating
> user input into a query is dangerous, and gives the PreparedStatement fix.
> The confidence bar is the CodeBERT score."

**Minute 2–3: why it is AST-based**

> "Notice the query here is `WHERE name='" + name + "'` — the SQL string itself
> contains quotes. A regex-based detector breaks on that, and mine did during
> development. Working on the AST instead, I look for a binary plus-expression
> passed to `executeQuery`, so quotes inside the literal are irrelevant. There's
> a regression test for exactly this case."

**Minute 3–4: the honest AI answer**

Get ahead of the question — do not wait to be caught out.

> "I should be clear about what CodeBERT is doing. It's a base encoder with no
> vulnerability classification head, so it cannot decide on its own whether code
> is vulnerable. The rule engine decides *what* the issue is. CodeBERT embeds
> the code and an English description of the weakness and measures cosine
> similarity — that's the confidence score. I've marked the seam in the code
> where a fine-tuned classifier would replace this layer."

**Minute 4–5: degraded mode — the strongest moment**

Switch to the Python terminal. Press **Ctrl+C**. Go back to the browser and
refresh.

> "The banner is now red — DEGRADED. Watch what happens if I upload the same
> file again."

Upload it. Findings still appear.

> "The static rule engine runs entirely inside the JVM and never depends on the
> AI service. Eight of my nine vulnerability classes still work. The run is
> recorded as DEGRADED in the database so you can tell the two apart later. The
> AI client is written so it never propagates a network failure — and I test
> that with MockWebServer simulating a 500, a dropped connection, and a stopped
> server."

**Minute 5–6: persistence**

Open **History**.

> "Every analysis is persisted. Here's the SUCCESS run and the DEGRADED run side
> by side."

Open the H2 console and run:

```sql
SELECT id, file_name, total_findings, risk_score, ai_engine_status
FROM analysis_records ORDER BY analysed_at DESC;
```

> "Two tables — one row per analysis, one row per finding, with a foreign key
> and cascade delete."

---

## Questions you should expect

Full answers are in the README's [Viva Questions](../README.md#viva-questions)
section. The ones most likely to come up, with the one-line version:

| Question | Short answer |
|---|---|
| Is the model fine-tuned? | No. Base encoder, used for confidence scoring, not classification. Say this before being asked. |
| Why two languages? | JavaParser needs the JVM; transformers need Python. The HTTP boundary is also what makes degraded mode possible. |
| Why not React? | The analysis engine is the project; a build pipeline wouldn't improve it. |
| What if the AI dies? | Demonstrate it rather than answering. |
| False positives? | No taint analysis — I see concatenation, not whether the value is user-controlled. Honest and specific beats vague. |
| Is this production-ready? | No. It's an architecture demonstration, not a SonarQube replacement. |

---

## Traps to avoid

**Do not claim CodeBERT detects OWASP vulnerabilities.** Any examiner who knows
ML will ask one follow-up and the claim collapses. The honest version is
genuinely more impressive because it shows you understand what the model does.

**Do not say "it uses AI" as if that explains anything.** Say what the model
takes as input, what it outputs, and what you do with that output.

**Do not promise accuracy numbers you have not measured.** If asked about your
false-positive rate: run the tool over a handful of files, count manually, and
quote a real number. "I haven't measured it formally, but on the sample files I
tested it flagged N things and M were genuine" is a much better answer than
"low".

**Do not let the model download happen live.** Verify the cache the night
before.

---

## If something breaks mid-demo

| Symptom | Fix |
|---|---|
| Port 8080 busy | `set SERVER_PORT=8081` and restart |
| AI service won't start | `set DEVSENTINEL_SKIP_MODEL=1` — rule-only mode still demos fully |
| Model download stalls | Same as above. Then explain rule-only mode — it is a designed feature, not an excuse |
| Maven can't resolve deps | You are offline; `mvn -o spring-boot:run` uses your local cache |
| Upload rejected | Check the file ends in `.java` and is under 1 MB |
| No findings appear | You uploaded a clean file — upload `samples/VulnerableExample.java` |
| Everything is broken | Play the backup video. This is why you recorded it. |

---

## Numbers worth memorising

- **9** vulnerability classes; **8** detected by the JVM rule engine alone
- **5** of the OWASP Top 10 2021 categories mapped
- **28** Python tests; **6** Java test classes
- **2** database tables
- **512** tokens — CodeBERT's positional limit, which is why snippets are
  truncated
- **4** — bounded concurrency on AI calls, because the Python service holds one
  model in one process
