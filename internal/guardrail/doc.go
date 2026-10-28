// Package guardrail holds no code. Its tests turn the CLAUDE.md guardrails
// into checks that fail `go test ./...`, so a change that crosses one stops
// at the test run instead of relying on someone remembering the rule.
//
// A failing test here is a stop sign, not a bug to work around: loosening a
// rule is a guardrail change and needs a human's confirmation first.
//
// The checks are static and deliberately coarse. They catch the obvious ways
// in (an import, a call to a well-known function), not every possible one.
package guardrail
