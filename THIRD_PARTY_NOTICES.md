# Third-party notices

## Open Cybersecurity Schema Framework

Drishti vendors the OCSF schema payload from release `1.9.0` from
<https://github.com/ocsf/ocsf-schema> at commit
`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`.

OCSF is licensed under the Apache License 2.0. Its upstream `LICENSE`, `NOTICE`,
source definitions, and project history files are retained under
`third_party/ocsf-schema/`.

The attested vendor-tree digest excludes `.github/**` and `.vscode/**`, which
contain upstream repository automation/editor settings rather than schema
contract data and are never executed by Drishti's build or runtime.

Drishti's separately maintained `schemas/drishti-extension/` is not part of the
official OCSF project. Its extension UID `9001` is private and unregistered; it
must not be presented as an allocation from the OCSF Extensions Registry.
