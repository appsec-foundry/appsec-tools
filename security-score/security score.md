# Security Score explained

The default engine checks selected patterns in source files, dependencies, and available repository settings. It reports a score from **0 to 100: higher is better**. The score describes what these checks found; it is neither a percentage of requirements met nor an estimate of attack probability.

## How the score is calculated

1. Each assessed area, such as execution or transport, starts with 100 points.
2. Every finding deducts points from its area. More severe findings deduct more points. Repeated findings count each time, including across files.
3. The most severe finding also sets an upper limit for that area's score. Use the lower result: the points left after deductions or this limit. Scores cannot fall below 0.
4. The **lowest assessed area score** becomes the repository score. Stronger areas cannot offset a weaker area.

| Finding severity | Deduction per finding | Area score cannot exceed |
| --- | ---: | ---: |
| Critical | 50 points | 39 |
| High | 25 points | 59 |
| Medium | 10 points | 79 |
| Low | 3 points | 89 |

The upper limit makes sure that a severe finding is visible in the grade, even when it is the only finding.

## Examples

| Findings | Calculation | Repository score |
| --- | --- | --- |
| One high finding | 100 − 25 = 75, limited to 59 | **59 (E)** |
| Two high findings in the same area | 100 − 50 = 50, below the limit of 59 | **50 (E)** |
| One high finding in each of two areas | Each area scores 59; the lowest wins | **59 (E)** |

These examples assume no other area scores lower. Fixing a finding may leave the headline unchanged if a severity limit or another area still determines the result. Use `--details` to see the findings and calculation for each area.

## Grades and missing scores

| Score | Grade |
| --- | --- |
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 50–59 | E |
| 0–49 | F |

**100 (A) means the recognized checks made no deductions.** Always consider coverage. Since scoring version 3, an unclear application check or recognized unsupported application source prevents a repository score. Unknown host settings alone do not block a score. Unknowns are not treated as point deductions.

| Result | Meaning |
| --- | --- |
| `partial` | Recognized evidence exists alongside unknown application coverage. An observed pattern index remains available, without a repository grade. |
| `undetermined` | No recognized source or dependency evidence is available. Host settings alone are insufficient. |
| `incomplete` | Required processing failed or reached a limit, such as the time budget. |

These results include no repository score or grade. Since scoring version 4, `observed_score` and origin-group indices preserve recognized patterns for partial and incomplete results. They do not establish application safety. Detailed text groups repeated candidates and reports parser issues once per file; JSON/YAML retain individual locations. Path hints separate source, tests, examples, assets, build files, and host settings without assuming which files run in production or silently excluding them. Compare indices only for the same engine, compatible scoring and rule versions, and similar scan coverage.

The default budget is 60 seconds. For repository URLs, downloads stop early
enough to reserve analysis time. Available sources still produce an observed
index when download time, entry-count or byte limits prevent a complete scan.
Detailed text (`--detail` or `--details`) shows category subscores, deductions,
located findings, files checked and selection limits. Normal text contains only
the result line; an incomplete index ends
with `(partial)` and retains exit status 1. Repositories with no recognized source
evidence cannot receive a numeric indication.

## Changes use relevance instead of points

For selected changes, the tool reports **high**, **medium**, **low**, or **unclear** security relevance. It asks which security-related behavior the change touches, rather than assigning a repository score.

A change to an access check can have high relevance even when it fixes a weakness. Ordinary documentation edits can be low; changes the rules cannot classify remain unclear. The strongest recognized indication determines the level.

## Further details

The optional Analyzer engine has its own scoring policy; see [engines and compatibility](references/compatibility.md). For check coverage, scan limits, the exact formula, and maintaining the rules, see the [technical scoring reference](references/scoring.md).
