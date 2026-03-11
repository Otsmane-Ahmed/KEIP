"""
KEIP .pth File Audit Scanner
Detects malicious .pth file planting during pip install.

Python automatically executes .pth files found in site-packages every time
the interpreter starts. A malicious package can abuse this to achieve
persistence by dropping a .pth file during installation.

This module snapshots .pth files before and after a pip install,
then alerts the user if any new .pth files were planted.
"""

import os
import sys
import glob
import site
import subprocess
import hashlib


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Known safe .pth files from standard Python tooling
# These contain executable code but are legitimate and expected
SAFE_PTH_FILES = {
    "distutils-precedence.pth",   # setuptools
    "easy-install.pth",           # setuptools/easy_install
    "setuptools.pth",             # setuptools
    "pip-strapped.pth",           # pip bootstrap
    "virtualenv.pth",             # virtualenv
    "coverage.pth",               # coverage.py
    "pytest-cov.pth",             # pytest-cov
}


def get_site_packages_dirs():
    """Get all site-packages directories (global + active venv)."""
    dirs = []

    # Global site-packages
    try:
        dirs.extend(site.getsitepackages())
    except AttributeError:
        pass

    # User site-packages 
    user_site = site.getusersitepackages()
    if user_site:
        dirs.append(user_site)

    # If inside a virtualenv, add venv site-packages
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        venv_lib = os.path.join(sys.prefix, 'lib')
        if os.path.isdir(venv_lib):
            for d in os.listdir(venv_lib):
                sp = os.path.join(venv_lib, d, 'site-packages')
                if os.path.isdir(sp):
                    dirs.append(sp)

    # Deduplicate and filter to existing dirs
    seen = set()
    result = []
    for d in dirs:
        d = os.path.realpath(d)
        if d not in seen and os.path.isdir(d):
            seen.add(d)
            result.append(d)

    return result


def snapshot_pth_files(site_dirs):
    """
    Take a snapshot of all .pth files across the given site-packages directories.
    Returns a dict: {filepath: sha256_hash}
    """
    snapshot = {}
    for d in site_dirs:
        for pth_file in glob.glob(os.path.join(d, '*.pth')):
            try:
                with open(pth_file, 'rb') as f:
                    content = f.read()
                snapshot[pth_file] = hashlib.sha256(content).hexdigest()
            except (PermissionError, OSError):
                snapshot[pth_file] = None
    return snapshot


def has_executable_code(filepath):
    """
    Check if a .pth file contains executable code.
    Lines starting with 'import' are executed by Python's site.py.
    """
    try:
        with open(filepath, 'r', errors='replace') as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith('import ') or stripped.startswith('import\t'):
                    return True, stripped
    except (PermissionError, OSError):
        pass
    return False, None


def diff_snapshots(before, after):
    """
    Compare before and after snapshots.
    Returns:
        new_files: list of .pth files that were added
        modified_files: list of .pth files whose content changed
    """
    new_files = []
    modified_files = []

    for filepath, new_hash in after.items():
        if filepath not in before:
            new_files.append(filepath)
        elif before[filepath] != new_hash:
            modified_files.append(filepath)

    return new_files, modified_files


def audit_report(new_files, modified_files):
    """
    Print a security report about .pth file changes.
    Returns True if suspicious files were found.
    """
    suspicious = False

    if not new_files and not modified_files:
        print(f"{GREEN}[KEIP .pth AUDIT] No new or modified .pth files detected. All clear.{RESET}")
        return False

    # Check new files
    for filepath in new_files:
        basename = os.path.basename(filepath)
        if basename in SAFE_PTH_FILES:
            continue
        has_code, code_line = has_executable_code(filepath)
        if has_code:
            suspicious = True
            print(f"\n{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
            print(f"{RED}{BOLD}║    KEIP ALERT: MALICIOUS .pth FILE DETECTED!               ║{RESET}")
            print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
            print(f"{RED}  File: {filepath}{RESET}")
            print(f"{RED}  Executable code found: {code_line}{RESET}")
            print(f"{RED}  WARNING: This file will execute silently every time Python starts!{RESET}")
            print(f"{RED}  Recommendation: Delete this file immediately with:{RESET}")
            print(f"{RED}    rm {filepath}{RESET}")
        else:
            print(f"{YELLOW}[KEIP .pth AUDIT] New .pth file detected (path-only, no code): {filepath}{RESET}")

    # Check modified files
    for filepath in modified_files:
        basename = os.path.basename(filepath)
        if basename in SAFE_PTH_FILES:
            continue
        has_code, code_line = has_executable_code(filepath)
        if has_code:
            suspicious = True
            print(f"\n{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
            print(f"{RED}{BOLD}║    KEIP ALERT: .pth FILE MODIFIED WITH CODE!                   ║{RESET}")
            print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
            print(f"{RED}  File: {filepath}{RESET}")
            print(f"{RED}  Executable code found: {code_line}{RESET}")
            print(f"{RED}  WARNING: This file was modified during installation!{RESET}")
        else:
            print(f"{YELLOW}[KEIP .pth AUDIT] Modified .pth file detected: {filepath}{RESET}")

    return suspicious


def scan_existing_pth_files(snapshot):
    """
    Scan all existing .pth files for executable code.
    This catches previously planted malicious .pth files
    that were dropped before KEIP was installed or used.
    Returns True if any suspicious files were found.
    """
    suspicious = False
    for filepath in snapshot:
        basename = os.path.basename(filepath)
        if basename in SAFE_PTH_FILES:
            continue
        has_code, code_line = has_executable_code(filepath)
        if has_code:
            suspicious = True
            print(f"\n{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
            print(f"{RED}{BOLD}║    KEIP ALERT: EXISTING MALICIOUS .pth FILE FOUND!           ║{RESET}")
            print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
            print(f"{RED}  File: {filepath}{RESET}")
            print(f"{RED}  Executable code found: {code_line}{RESET}")
            print(f"{RED}  WARNING: This file executes silently every time Python starts!{RESET}")
            print(f"{RED}  Recommendation: Delete this file immediately with:{RESET}")
            print(f"{RED}    rm {filepath}{RESET}")
    return suspicious


def run_pip_with_audit(pip_args):
    """
    Run pip install with .pth file auditing.
    1. Scan existing .pth files for executable code
    2. Snapshot .pth files before install
    3. Run pip install
    4. Snapshot .pth files after install
    5. Report any new/modified .pth files
    """
    site_dirs = get_site_packages_dirs()

    if not site_dirs:
        print(f"{YELLOW}[KEIP .pth AUDIT] Warning: Could not locate any site-packages directories.{RESET}")
        # Still run pip, just skip the audit
        return subprocess.call([sys.executable, '-m', 'pip'] + pip_args)

    print(f"{GREEN}[KEIP .pth AUDIT] Scanning site-packages before install...{RESET}")
    for d in site_dirs:
        print(f"  Monitoring: {d}")

    before = snapshot_pth_files(site_dirs)
    print(f"  Found {len(before)} existing .pth file(s)")

    # Scan ALL existing .pth files for executable code
    print(f"{GREEN}[KEIP .pth AUDIT] Checking existing .pth files for executable code...{RESET}")
    found_existing_threat = scan_existing_pth_files(before)

    if not found_existing_threat:
        print(f"{GREEN}  All existing .pth files are clean.{RESET}")

    # Run the actual pip install
    print(f"{GREEN}[KEIP .pth AUDIT] Running pip install...{RESET}")
    ret = subprocess.call([sys.executable, '-m', 'pip'] + pip_args)

    # Post-install audit
    print(f"\n{GREEN}[KEIP .pth AUDIT] Scanning site-packages after install...{RESET}")
    after = snapshot_pth_files(site_dirs)

    new_files, modified_files = diff_snapshots(before, after)
    found_new_threat = audit_report(new_files, modified_files)

    if found_existing_threat or found_new_threat:
        print(f"\n{RED}{BOLD}[KEIP .pth AUDIT]   SUSPICIOUS .pth FILES FOUND! Review the alerts above.{RESET}")

    return ret


def run_scan():
    """
    Standalone scan: check all existing .pth files for executable code.
    Can be run anytime with: keip scan
    """
    site_dirs = get_site_packages_dirs()

    if not site_dirs:
        print(f"{YELLOW}[KEIP SCAN] Warning: Could not locate any site-packages directories.{RESET}")
        return 0

    print(f"{GREEN}[KEIP SCAN] Scanning all site-packages for malicious .pth files...{RESET}")
    for d in site_dirs:
        print(f"  Checking: {d}")

    snapshot = snapshot_pth_files(site_dirs)
    print(f"  Found {len(snapshot)} .pth file(s)")

    found_threat = scan_existing_pth_files(snapshot)

    if found_threat:
        print(f"\n{RED}{BOLD}[KEIP SCAN]   THREATS FOUND! Review the alerts above and delete the malicious files.{RESET}")
        return 1
    else:
        print(f"{GREEN}[KEIP SCAN] All .pth files are clean. No threats detected.{RESET}")
        return 0


def run_python_safe(python_args):
    """
    Safe python wrapper: scan for malicious .pth files before running python.
    Usage: keip python script.py
    """
    site_dirs = get_site_packages_dirs()

    if site_dirs:
        print(f"{GREEN}[KEIP] Scanning .pth files before execution...{RESET}")
        snapshot = snapshot_pth_files(site_dirs)
        found_threat = scan_existing_pth_files(snapshot)

        if found_threat:
            print(f"\n{RED}{BOLD}[KEIP] BLOCKED: Malicious .pth files detected!{RESET}")
            print(f"{RED}  Python execution was stopped to protect you.{RESET}")
            print(f"{RED}  Delete the malicious files listed above, then try again.{RESET}")
            print(f"{RED}  Or run with: keip python --force {' '.join(python_args)}{RESET}")
            return 1
        else:
            print(f"{GREEN}[KEIP] All .pth files are clean. Launching Python...{RESET}\n")

    # Run python with the user's arguments
    return subprocess.call([sys.executable] + python_args)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 pth_audit.py install <package>   # pip install with .pth audit")
        print("  python3 pth_audit.py scan                # scan for malicious .pth files")
        print("  python3 pth_audit.py python <script>     # safe python execution")
        sys.exit(1)

    command = sys.argv[1]

    if command == "scan":
        sys.exit(run_scan())
    elif command == "python":
        args = sys.argv[2:]
        # Handle --force flag
        if args and args[0] == "--force":
            args = args[1:]
            sys.exit(subprocess.call([sys.executable] + args))
        sys.exit(run_python_safe(args))
    else:
        
        ret = run_pip_with_audit(sys.argv[1:])
        sys.exit(ret)

