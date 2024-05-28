## Overview
`germy` is an `N_GSM` Linux kernel privilege escalation exploit for versions `5.15-rc1` to `6.6-rc1`. See `TECHNICAL_DETAILS.md` for information on the vulnerabilities and exploit techniques used.

Tested on:
 - Ubuntu LTS 20.04.6 (5.15.x) and 22.04.4 (6.5.x)
 - Ubuntu non-LTS 23.10 (6.5.x)
 - Debian 12.5 (6.1.x)

## Usage
Run `make debug` or `make release` to produce either `germy_debug` or `germy_release`.

The release version does not print any revealing information about the exploit procedure, and the binary is stripped. See `Makefile` for details.

The exploit can be run as: `./germy`. The exploit can also be run with the `--retry` flag; this will retry the exploit in a loop until it succeeds. This _may_ compromise system stability.

## Assumptions
 - Target system is `x86_64`, with 8-byte pointers and 4-byte integers:
    - `sizeof(u64) == sizeof(void*) == sizeof(uintptr_t)`
    - `sizeof(u32) == 4 == sizeof(i32)`
 - struct randomization is not enabled

## License
This software package is provided as-is; don't do anything bad with it, cheers.