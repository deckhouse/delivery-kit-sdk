# AGENTS

## Software Engineering Principles

- SOLID (SRP/OCP/LSP/ISP/DIP) for extensibility and safe change.
- DRY: one source of truth for business rules and schemas.
- KISS and YAGNI: prefer the simplest solution that meets current needs.
- Separation of Concerns; high cohesion, low coupling.
- Composition over inheritance; avoid deep hierarchies.
- Fail fast; validate inputs and assumptions early.
- Design for testability; keep code readable over clever.
- Security by design: least privilege and safe defaults.
- Observability by design: logs, metrics, traces for critical paths.

##  BDD (Behavior-Driven Development) Process

- Behavior First: Define expectations in Gherkin (Given/When/Then) before implementation.
- Single Source of Truth: User Stories and Acceptance Criteria are the primary drivers for code and tests.
- Red-Green-Refactor: Always start with a failing test; implement just enough to pass; refactor for quality.
- Living Documentation: Ensure feature files remain up-to-date and reflect actual system behavior.
- Small Iterations: Break down complex features into small, testable behaviors for better AI accuracy.
- Intent over Implementation: Tests should describe *what* the system does, not *how* it does it.
