# Third-party licenses

This directory contains unchanged license and notice files for the 16 Go
module versions explicitly pinned in [go.mod](../../go.mod), plus the Go
`go1.27.3` standard library and runtime license. Include this directory and
the project [NOTICE](../../NOTICE) when distributing Known Device binaries.

The module files come from the corresponding pinned Go module archives.
[manifest.json](manifest.json) records the upstream filename, public source
archive and SHA-256 digest of each copied file. Module archive checksums are
recorded in [go.sum](../../go.sum). The license texts retain their upstream
copyright statements, spacing and terms.

| Module | Pinned version | License | Copied files |
| --- | --- | --- | --- |
| `github.com/eclipse/paho.golang` | `v0.23.0` | EPL-2.0 or BSD-3-Clause through EDL-1.0 | [LICENSE](github.com/eclipse/paho.golang@v0.23.0/LICENSE), [EPL](github.com/eclipse/paho.golang@v0.23.0/epl-v20), [EDL](github.com/eclipse/paho.golang@v0.23.0/edl-v10) |
| `github.com/google/jsonschema-go` | `v0.4.3` | MIT | [LICENSE](github.com/google/jsonschema-go@v0.4.3/LICENSE) |
| `github.com/spf13/cobra` | `v1.10.2` | Apache-2.0 | [LICENSE.txt](github.com/spf13/cobra@v1.10.2/LICENSE.txt) |
| `go.yaml.in/yaml/v3` | `v3.0.6` | Apache-2.0 and MIT for different source files | [LICENSE](go.yaml.in/yaml/v3@v3.0.6/LICENSE), [NOTICE](go.yaml.in/yaml/v3@v3.0.6/NOTICE) |
| `modernc.org/sqlite` | `v1.61.0` | BSD-3-Clause for the Go driver; SQLite public domain; additional bundled notices | [LICENSE](modernc.org/sqlite@v1.61.0/LICENSE), [third-party notices](modernc.org/sqlite@v1.61.0/LICENSE-3RD-PARTY.md), [SQLite](modernc.org/sqlite@v1.61.0/LICENSE-SQLITE), [sqlite-vec](modernc.org/sqlite@v1.61.0/LICENSE-SQLITE_VEC) |
| `github.com/dustin/go-humanize` | `v1.1.0` | MIT | [LICENSE](github.com/dustin/go-humanize@v1.1.0/LICENSE) |
| `github.com/google/uuid` | `v1.6.0` | BSD-3-Clause | [LICENSE](github.com/google/uuid@v1.6.0/LICENSE) |
| `github.com/inconshreveable/mousetrap` | `v1.1.0` | Apache-2.0 | [LICENSE](github.com/inconshreveable/mousetrap@v1.1.0/LICENSE) |
| `github.com/mattn/go-isatty` | `v0.0.24` | MIT | [LICENSE](github.com/mattn/go-isatty@v0.0.24/LICENSE) |
| `github.com/ncruces/go-strftime` | `v1.1.0` | MIT | [LICENSE](github.com/ncruces/go-strftime@v1.1.0/LICENSE) |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | BSD-3-Clause | [LICENSE](github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec/LICENSE) |
| `github.com/spf13/pflag` | `v1.0.10` | BSD-3-Clause | [LICENSE](github.com/spf13/pflag@v1.0.10/LICENSE) |
| `golang.org/x/sys` | `v0.49.0` | BSD-3-Clause | [LICENSE](golang.org/x/sys@v0.49.0/LICENSE) |
| `modernc.org/libc` | `v1.79.0` | BSD-3-Clause and bundled third-party notices | [LICENSE](modernc.org/libc@v1.79.0/LICENSE), [third-party notices](modernc.org/libc@v1.79.0/LICENSE-3RD-PARTY.md) |
| `modernc.org/mathutil` | `v1.7.1` | BSD-3-Clause | [LICENSE](modernc.org/mathutil@v1.7.1/LICENSE), [mersenne/LICENSE](modernc.org/mathutil@v1.7.1/mersenne/LICENSE) |
| `modernc.org/memory` | `v1.12.1` | BSD-3-Clause with supplementary notices | [LICENSE](modernc.org/memory@v1.12.1/LICENSE), [Go](modernc.org/memory@v1.12.1/LICENSE-GO), [mmap-go](modernc.org/memory@v1.12.1/LICENSE-MMAP-GO), [logo reference](modernc.org/memory@v1.12.1/LICENSE-LOGO) |
| Go standard library and runtime | `go1.27.3` | BSD-3-Clause | [LICENSE](go@go1.27.3/LICENSE) |

Paho supplies two licensing alternatives. Both upstream license texts are
preserved. The YAML module applies MIT to its libyaml-derived files and
Apache-2.0 to its remaining files; its complete upstream NOTICE is also
reproduced in the project NOTICE.

SQLite and libc include notices for embedded code and inherited components,
including SQLite, musl, Go, go-netdb and NixOS material. Their complete
upstream notice documents are preserved, including upstream classifications
of runtime, test and module-graph components. Those classifications describe
the upstream projects; inclusion of a notice here does not assert that every
listed component is compiled into Known Device. The optional sqlite-vec
notice and memory logo reference are retained as supplied; this directory
contains no copied logo assets.

When dependency versions change, copy the notices from the new pinned
archives and update this inventory, the manifest and the project NOTICE.
