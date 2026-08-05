# Spike: Maven / Gradle build-time execution threat model (ticket 0038)

> Research note — decides the shape of a future Maven/Gradle analyzer before any
> code. Outcome: **GO, narrowly scoped.** Not yet implemented.

## [1] What executes, and when

Unlike npm (`hasInstallScript` per package) and Python/Ruby (a sdist/gem runs
`setup.py` / `extconf.rb` at install), the JVM ecosystems do **not** run per-package
install scripts on dependency resolution. The attacker-controllable execution lives
in the **build script / build plugins**, which run arbitrary code during a `mvn` /
`gradle` invocation:

- **Maven** — `pom.xml` binds **build plugins** to lifecycle phases; a plugin
  (`maven-antrun-plugin`, `exec-maven-plugin`, a custom mojo) executes arbitrary Java
  at `mvn package`/`verify`/`install`. `~/.m2/settings.xml` can also redirect the
  repository (a supply-chain redirect analog to `.npmrc`).
- **Gradle** — `build.gradle` / `build.gradle.kts` **is** a Groovy/Kotlin program
  executed at configuration time — strictly more open than Maven. Any `gradle`
  invocation runs it; `gradlew` (the committed wrapper) even fetches and runs a Gradle
  distribution pinned in `gradle-wrapper.properties`.

**Key distinction:** the dangerous unit is a **build-script / plugin change**, not
"a dependency was added." A transitive dependency does not, by itself, run code at
resolution.

## [2] The dependency-change signal without a lockfile

Maven has **no lockfile by default** (versions in `pom.xml`, transitive versions
resolved at build). Gradle can opt into `gradle.lockfile`. So the clean, deterministic
"newly added dependency" signal the npm/Ruby/Python analyzers rely on is **not
reliably available**. The high-signal, low-false-positive change to watch is instead:

- a new/changed `<build><plugins>` entry in `pom.xml` (executes at build), and
- an added/changed `build.gradle(.kts)` or `gradle-wrapper.properties` (executes /
  pins the toolchain).

These are the true **repo-committed install-time-code** analog of `setup.py`.

## [3] Mapping onto the existing graph

It fits the established shape with **no engine change**:

- Treat a changed `pom.xml` build-plugin block / `build.gradle(.kts)` as an
  install-time-code manifest — a `dependency` node with `hasInstallScript: true`,
  `ecosystem: 'jvm'`, **diff-gated** (added/changed only), exactly like `pydeps`
  handles `setup.py`.
- The engine's existing cross-layer synthesis connects it (`runs-in`) to a
  fork-triggerable CI job that runs a build and holds a secret.
- Teach the CI install/build detector (`INSTALL_RE`) about `mvn`, `gradle`,
  `./gradlew`.
- Labeling reuses the `new-dependency` archetype → `ASI04` / `MCP04`.

## [4] Recommendation — GO, narrowly

Build a `maven` (JVM) analyzer that models **build-script / plugin execution** as the
install-time vector, following the `pydeps`/RubyGems template:

- **In scope:** `pom.xml` `<build>` plugin diff, `build.gradle(.kts)` diff,
  `gradle-wrapper.properties` change; `mvn`/`gradle` install-step detection; the
  `.m2/settings.xml` repository-redirect signal (mirror `.npmrc`).
- **Out of scope (v1):** full transitive-dependency graph / version-diff modeling —
  there is no reliable universal lockfile, and per-dependency CVE work belongs to the
  opt-in advisory enrichment (0036), not a bespoke resolver.
- **Effort:** ~M. **Risk:** medium — the plugin-vs-dependency distinction must be
  explained clearly (a reviewer will expect "added dependency" flags that we
  deliberately don't emit), and Gradle's arbitrary-code build scripts mean the mere
  presence of a changed `build.gradle` on a fork-triggerable secret-bearing build job
  is the finding.

File the implementation as a new ticket when the ecosystem is prioritized; this note
is the design input.
