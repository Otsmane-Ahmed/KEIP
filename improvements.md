# KEIP Improvements Log

This document tracks all improvements made to KEIP, explaining the "how" and "why" for each implemented fix.

## 1. Remove Strict Sudo Requirement (CAP_BPF)
**Status:** Planning

**Why:** Keip currently requires strict root access (`sudo`). This is a huge friction point for developers and CI/CD pipelines, making it hard to deploy without granting full system administrative privileges.

**How we fixed it:**
To avoid granting global eBPF privileges to the system's `python3` binary (which would be a massive security flaw where any python script could load kernel hooks), we introduced a dedicated python binary strategy:
1. `setup.sh`: Added `libcap2-bin` to install the `setcap` tool.
2. `install.sh`: Creates an isolated copy of Python at `/opt/keip/keip-python` and assigns it `cap_bpf,cap_sys_admin,cap_perfmon=ep`.
3. `install.sh`: The global wrapper `/usr/local/bin/keip` now explicitly uses this dedicated binary.
4. `run_keip.sh`: Edited to look for `cap_bpf` on the python binary if not run as root.
5. `src/keip_pip_monitor.py`: Removed the hardcoded `os.geteuid() != 0` check. If capabilities are missing, the BCC module will fail gracefully on its own.
6. `README.md`: Updated commands to run without `sudo`.

## 2. Detect `.pth` File Planting (Post-Install Audit)
**Status:** Planning

**Why:**
As explained by the developer, Python's `.pth` files present a massive persistence vulnerability that bypasses KEIP's current network monitoring logic.

**The Bypass Mechanism:**
So this .pth fix is for people who use a global environment (don't use venv), and for people who reuse venvs across many projects. A malicious package can drop a `.pth` file in the `site-packages` folder (either the global environment or the venv environment), and whenever you run python to execute your code, python will check the `site-packages` and execute whatever `.pth` is there even if it is related to your python code or not (even if its related to your imports or not on your script). Since its not a child of pip install, KEIP won't intercept the malicious call.

**How we fixed it:**
1. `src/pth_audit.py`: Created a new module that snapshots all `.pth` files in every `site-packages` directory (global + venv) before and after a `pip install`. It compares the snapshots and alerts the user if any new `.pth` files containing executable code (`import ...` lines) were planted. It also includes a whitelist of known safe `.pth` files (e.g. `distutils-precedence.pth` from setuptools) to avoid false positives.
2. `keip install <package>`: Wraps pip install with the `.pth` audit (before + after snapshot).
3. `keip scan`: Standalone scanner that checks all existing `.pth` files for executable code at any time.
4. `keip python <script>`: Safe python wrapper that scans for malicious `.pth` files **before** running the script. If threats are found, execution is **blocked**. Supports `--force` to override.
5. `install.sh`: Updated the `keip` wrapper to route all new subcommands to `pth_audit.py`.
6. `README.md`: Documented the new commands.
