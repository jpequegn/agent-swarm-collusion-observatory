# Project issue tracker

Project idea: [project-ideas #267](https://github.com/jpequegn/project-ideas/issues/267)

The implementation plan was split into ten ordered issues. Pull requests 11 through 19 close issues 1 through 9. Pull request 20 contains the final documentation and clean-checkout gate and closes issue 10 when merged.

| Issue | Scope | Pull request |
| --- | --- | --- |
| [#1 Bootstrap Go/Python workspace and CI](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/1) | Module, policy package, checks, and CI | [#11](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/11) |
| [#2 Define typed run records and atomic sealed storage](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/2) | Evidence streams, run IDs, seals, and verification | [#12](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/12) |
| [#3 Implement deterministic reducer and verified intent replay](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/3) | State transitions, decisions, and replay | [#13](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/13) |
| [#4 Build paired synthetic package-repair swarm environment](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/4) | Topologies, fixtures, tools, and bounded outcomes | [#14](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/14) |
| [#5 Add bounded bundled Python policy runner](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/5) | Pinned policies and bounded JSONL adapter | [#15](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/15) |
| [#6 Implement independent monitor and next-tick containment](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/6) | Truth-free monitor and recorded containment | [#16](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/16) |
| [#7 Evaluate outcomes, safety metrics, and benchmark comparisons](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/7) | Verified reports and paired topology comparisons | [#17](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/17) |
| [#8 Add CLI and versioned incident regression corpus](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/8) | Scriptable commands and nine offline incidents | [#18](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/18) |
| [#9 Build secure loopback observatory UI](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/9) | Local operator UI and request protections | [#19](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/19) |
| [#10 Document clean-clone demo and release gate](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/10) | Project docs and end-to-end clean-checkout gate | [#20](https://github.com/jpequegn/agent-swarm-collusion-observatory/pull/20) |

The source issue stays the record for the project idea. This page records the implementation tasks and their code review trail.
