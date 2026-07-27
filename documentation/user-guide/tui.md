# Interactive DevSecOps Fullscreen Dashboard (TUI)

Vigil includes a Lazygit / `btm` inspired fullscreen terminal dashboard (`StateExplorer`) designed for real-time security auditing and vulnerability inspection.

```
🛡️ VIGIL LAZYGIT DEVSECOPS DASHBOARD | 14 VULNS | 2 SECRETS | 1 IAC RISKS
[1] Vulns (SCA)  [2] Secrets  [3] IaC Security  [4] Licenses  [5] Dep Graph
Group: [FLAT] | Filter: [ALL] | Search: none | Active Pane: [1] | Maximize: [false]
╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│  [1] Security Findings Table                                                                                                      │
│ DOMAIN      SEVERITY      TARGET / PACKAGE            ID / RULE                   REASON SUMMARY                                  │
│───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────│
│ SCA         MEDIUM        storybook@8.3.2             CVE-2025-68429              A vulnerability affects storybook@8.3.2...      │
│ SCA         MEDIUM        swiper@11.1.14              CVE-2026-27212              Prototype pollution in swiper...                │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────╮╭──────────────────────────────────────────────╮╭───────────────────────────────╮
│ 💡 [2] Reason Why Flagged     ││  [3] Detailed Inspection                     ││  [4] Dependency Tree Path     │
│A vulnerability affects        ││Target Package: storybook@8.3.2               ││ Root: storybook@8.3.2         │
│storybook@8.3.2 tracked as     ││ID / Rule: CVE-2025-68429                     ││ └── storybook@8.3.2          │
│CVE-2025-68429.                ││Severity:   MEDIUM                            ││     [VULNERABLE TARGET]       │
╰───────────────────────────────╯╰──────────────────────────────────────────────╯╰───────────────────────────────╯
 [Tab] Focus Pane | [w/f] Maximize | [↑/↓/k/j] Navigate/Scroll | [1-5] View | [/] Search | [g] Group | [e] Export | [q] Quit
```

---

## 📐 Layout Architecture

The TUI is organized into a **2-Tier Grid**:

1. **Top Section (Full-Width Table Pane)**:
   - **`[1] Security Findings Table`**: Displays all findings across 5 rich columns (`DOMAIN`, `SEVERITY`, `TARGET / PACKAGE`, `ID / RULE`, `REASON SUMMARY`).
2. **Bottom Section (3 Side-by-Side Panes)**:
   - **`💡 [2] Reason Why Flagged`** (Width: 25%): Full word-wrapped explanation detailing why the selected finding was flagged.
   - **`󰈔 [3] Detailed Inspection`** (Width: 50%): Deep inspection pane with CVSS score & vector, vulnerability context, and recommended remediation.
   - **`󰒍 [4] Dependency Tree Path`** (Width: 25%): Interactive graph path showing exact tree hierarchy (`Root ➔ Dep ➔ Target [VULNERABLE]`).

---

## ⌨️ Keybindings & Controls

### Navigation & Focus

| Key | Action |
| --- | --- |
| `Tab` / `Shift+Tab` | Cycle active pane focus between Panes `[1]`, `[2]`, `[3]`, `[4]` |
| `w` / `f` | Toggle 100% fullscreen maximization for the currently active pane |
| `↑` / `↓` / `k` / `j` | Navigate items in Table `[1]` or scroll viewports in `[2]`, `[3]`, `[4]` |

### Tabs (`[1-5]`)

| Key | Tab View | Content |
| --- | --- | --- |
| `1` | `Vulns (SCA)` | Software Composition Analysis vulnerabilities |
| `2` | `Secrets` | Hardcoded AWS keys, PAT tokens, SSH keys, DB credentials |
| `3` | `IaC Security` | Dockerfile & GitHub Actions security linting issues |
| `4` | `Licenses` | Permissive vs Copyleft (GPL/AGPL) license risk analysis |
| `5` | `Dep Graph` | Complete dependency graph nodes |

### Filtering & Search

| Key | Action |
| --- | --- |
| `g` | Cycle grouping mode (`FLAT` ➔ `BY PACKAGE` ➔ `BY SEVERITY`) |
| `c` | Quick filter: `CRITICAL` severity only |
| `h` | Quick filter: `HIGH` severity only |
| `m` | Quick filter: `MEDIUM` severity only |
| `l` | Quick filter: `LOW` severity only |
| `a` / `Esc` | Reset all filters and search query |
| `/` | Open live interactive search prompt |

### Export & Quit

| Key | Action |
| --- | --- |
| `e` | Open interactive Export Report Dialog modal (`JSON`, `CSV`, `Markdown`, `CycloneDX`, `SPDX`) |
| `q` / `Ctrl+C` | Exit TUI dashboard |
