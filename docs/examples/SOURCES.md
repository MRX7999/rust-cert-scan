# Example provenance

The JSON in this directory is an extract and a reading of published scan files. `certscan` did not produce them.

| File | Recorded | sha256 | Bytes |
|---|---|---|---|
| [expired.badssl.com.json](https://github.com/secureCodeBox/secureCodeBox/blob/main/scanners/sslyze/parser/__testFiles__/expired.badssl.com.json) | 2025-11-05T12:20:48Z | `ebdd327b89e6ae40b63b693ea22de5661a7be4749209b3d4b39283569002821f` | 224627 |
| [self-signed.badssl.com.json](https://github.com/secureCodeBox/secureCodeBox/blob/main/scanners/sslyze/parser/__testFiles__/self-signed.badssl.com.json) | 2025-11-05T12:15:09Z | `bee06aa8c5fc8a5f2951795e60b6688ef61706634b417042ee7b193db198ff91` | 208061 |
| [revoked.badssl.com.json](https://github.com/secureCodeBox/secureCodeBox/blob/main/scanners/sslyze/parser/__testFiles__/revoked.badssl.com.json) | 2025-11-05T12:14:27Z | `b6d4ad5cbb468b624d192a322008211b8709285f67cf11384079072d5d2c76da` | 284463 |
| [untrusted-root.badssl.com.json](https://github.com/secureCodeBox/secureCodeBox/blob/main/scanners/sslyze/parser/__testFiles__/untrusted-root.badssl.com.json) | 2025-11-05T12:16:24Z | `2680e45dc295c290609022509c95f0f79c6ea76637f7f318828985b2489f082d` | 217418 |
| [wrong.host.badssl.com.json](https://github.com/secureCodeBox/secureCodeBox/blob/main/scanners/sslyze/parser/__testFiles__/wrong.host.badssl.com.json) | 2025-11-05T12:17:00Z | `c4affbcb6a9b03f64e9686b9d810a3994439b39fe549d587d7f8263c14a1bab6` | 212558 |
| [tls-v1-0.badssl.com_1010.json](https://github.com/secureCodeBox/secureCodeBox/blob/main/scanners/sslyze/parser/__testFiles__/tls-v1-0.badssl.com_1010.json) | 2025-11-05T12:15:53Z | `e2fceaf7553d64a9e19da8f5d75b63b043ca39aaa2dd7a58aecedf017e3b8ce5` | 313326 |

Tool: SSLyze 6.2.0 ([nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)). The fixtures are published by [secureCodeBox](https://github.com/secureCodeBox/secureCodeBox) under Apache-2.0.

```text
SPDX-FileCopyrightText: the secureCodeBox authors
SPDX-License-Identifier: Apache-2.0
```

The hosts are the public [badssl.com](https://badssl.com/) testbed. These files are not a permission to scan any other system.

The full fixture JSON is not vendored. [published-extracts.json](published-extracts.json) keeps the fields used by the charts and by the schema reading. A field that the source file does not contain is omitted.
