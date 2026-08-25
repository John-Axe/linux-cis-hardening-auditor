"""Additional authentication/account-integrity checks (CIS sections 6.2.x
and 5.4.x, extending checks/auth.py) - duplicate UID/GID/name detection,
root PATH integrity, dangerous dotfiles in home directories, home directory
existence/ownership, the shadow group, /etc/group referential integrity,
legacy NIS '+' entries, password hashing algorithm, and default account
inactivity lock.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_lines, read_text

CATEGORY = "auth"


def _passwd_entries() -> list[dict[str, str]] | None:
    lines = read_lines("/etc/passwd")
    if lines is None:
        return None
    entries = []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 7:
            continue
        entries.append(
            {
                "name": fields[0],
                "uid": fields[2],
                "gid": fields[3],
                "home": fields[5],
                "shell": fields[6],
            }
        )
    return entries


def _group_entries() -> list[dict[str, str]] | None:
    lines = read_lines("/etc/group")
    if lines is None:
        return None
    entries = []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 4:
            continue
        entries.append({"name": fields[0], "gid": fields[2], "members": fields[3]})
    return entries


def _interactive_users(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    for e in entries:
        try:
            uid = int(e["uid"])
        except ValueError:
            continue
        if uid < 1000 or e["name"] == "nobody":
            continue
        if e["shell"].strip() in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            continue
        result.append(e)
    return result


def _duplicate_check(id: str, title: str, rationale: str, remediation: str, key_fn, source_desc: str, entries_fn):
    @register(id=id, title=title, category=CATEGORY, rationale=rationale, remediation=remediation)
    def _check() -> CheckResult:
        entries = entries_fn()
        if entries is None:
            return CheckResult(Status.NOT_APPLICABLE, f"{source_desc} could not be read.")
        seen: dict[str, int] = {}
        for e in entries:
            k = key_fn(e)
            seen[k] = seen.get(k, 0) + 1
        dupes = {k: c for k, c in seen.items() if c > 1}
        evidence = f"Checked {len(entries)} entries in {source_desc}."
        if not dupes:
            return CheckResult(Status.PASS, evidence + " No duplicates found.")
        return CheckResult(Status.FAIL, evidence + f" Duplicate(s): {dupes}")

    _check.__name__ = f"check_{id.replace('-', '_').replace('.', '_')}"
    return _check


_duplicate_check(
    "CIS-6.2.3", "No duplicate UIDs exist in /etc/passwd",
    "Two accounts sharing a UID are indistinguishable to the kernel and "
    "most tools - files 'owned' by one are equally accessible to both, and "
    "audit logs can't tell them apart.",
    "Assign each account a unique UID with usermod -u <new-uid> <name>.",
    lambda e: e["uid"], "/etc/passwd", _passwd_entries,
)
_duplicate_check(
    "CIS-6.2.4", "No duplicate GIDs exist in /etc/group",
    "Two groups sharing a GID grant identical file access to both "
    "groups' members, which usually indicates a configuration mistake "
    "rather than an intentional access grant.",
    "Assign each group a unique GID with groupmod -g <new-gid> <name>.",
    lambda e: e["gid"], "/etc/group", _group_entries,
)
_duplicate_check(
    "CIS-6.2.5", "No duplicate usernames exist in /etc/passwd",
    "Duplicate usernames create ambiguity about which entry (and which UID) "
    "applies for tools that look up by name, which can be abused to run as "
    "an unintended UID.",
    "Rename or remove the duplicate entry so each username appears once.",
    lambda e: e["name"], "/etc/passwd", _passwd_entries,
)
_duplicate_check(
    "CIS-6.2.6", "No duplicate group names exist in /etc/group",
    "Same ambiguity risk as duplicate usernames, applied to group name "
    "lookups.",
    "Rename or remove the duplicate entry so each group name appears once.",
    lambda e: e["name"], "/etc/group", _group_entries,
)


@register(
    id="CIS-6.2.7",
    title="root's PATH does not contain a relative or world-writable directory",
    category=CATEGORY,
    rationale="A relative entry (like '.') or a world-writable directory in "
    "root's PATH lets any local user plant a malicious binary that root "
    "might execute by name, a classic privilege-escalation trick.",
    remediation="Remove any relative or world-writable directory from root's PATH "
    "in /root/.bashrc, /root/.profile, or /etc/profile.",
)
def check_root_path_integrity() -> CheckResult:
    # Best-effort: inspects this process's own PATH, which is only truly
    # root's PATH when this audit itself is run as root - honestly reflects
    # that limitation in the evidence rather than claiming more than it knows.
    path_value = os.environ.get("PATH", "")
    entries = path_value.split(":")
    problems = []
    for entry in entries:
        if entry in ("", "."):
            problems.append(f"'{entry or '(empty)'}' (relative to cwd)")
            continue
        try:
            st = os.stat(entry)
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
        if st.st_mode & 0o002:
            problems.append(f"{entry} (world-writable)")
    evidence = f"PATH={path_value!r} (evaluated for the account running this audit, UID {os.getuid()})"
    if not problems:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" - problem entries: {', '.join(problems)}")


def _dangerous_dotfile_check(id: str, filename: str, rationale: str) -> None:
    @register(
        id=id,
        title=f"No interactive user has a .{filename} file in their home directory",
        category=CATEGORY,
        rationale=rationale,
        remediation=f"Review and remove any .{filename} file found: rm ~<user>/.{filename}",
    )
    def _check() -> CheckResult:
        entries = _passwd_entries()
        if entries is None:
            return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd could not be read.")
        interactive = _interactive_users(entries)
        found = []
        for e in interactive:
            candidate = os.path.join(e["home"], f".{filename}")
            if os.path.isfile(candidate):
                found.append(candidate)
        evidence = f"Checked {len(interactive)} interactive user home director(ies) for .{filename}."
        if not found:
            return CheckResult(Status.PASS, evidence + " None found.")
        return CheckResult(Status.FAIL, evidence + f" Found: {', '.join(found)}")

    _check.__name__ = f"check_no_dot_{filename}"


_dangerous_dotfile_check(
    "CIS-6.2.8", "netrc",
    "A .netrc file can store plaintext credentials for automated FTP/HTTP "
    "logins; if present it's a high-value target for any attacker who "
    "gains even unprivileged read access to that home directory.",
)
_dangerous_dotfile_check(
    "CIS-6.2.10", "forward",
    "A .forward file silently forwards a user's mail to another address "
    "(potentially external) - a common way to exfiltrate sensitive mail "
    "(e.g. password reset emails) after an account is compromised.",
)
_dangerous_dotfile_check(
    "CIS-6.2.11", "rhosts",
    "A .rhosts file grants passwordless rlogin/rsh trust to listed remote "
    "hosts/users - a legacy trust mechanism with no cryptographic "
    "authentication that should never be present on a hardened host.",
)


@register(
    id="CIS-6.2.12",
    title="All interactive users' home directories exist",
    category=CATEGORY,
    rationale="An account whose home directory is missing will get shell "
    "startup errors and, worse, some shells fall back to '/' as a working "
    "directory - the account still works, just in a confusing and "
    "potentially insecure state.",
    remediation="mkdir -p <home> && chown <user>:<user> <home>  # or fix the passwd entry if the path is wrong",
)
def check_home_dirs_exist() -> CheckResult:
    entries = _passwd_entries()
    if entries is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd could not be read.")
    interactive = _interactive_users(entries)
    missing = [f"{e['name']}:{e['home']}" for e in interactive if not os.path.isdir(e["home"])]
    evidence = f"Checked {len(interactive)} interactive user account(s)."
    if not missing:
        return CheckResult(Status.PASS, evidence + " All home directories exist.")
    return CheckResult(Status.FAIL, evidence + f" Missing: {', '.join(missing)}")


@register(
    id="CIS-6.2.13",
    title="All interactive users' home directories are owned by that user",
    category=CATEGORY,
    rationale="If a home directory is owned by someone other than its "
    "account, that other owner can read/modify the account's dotfiles "
    "(e.g. plant a malicious .bashrc), functionally hijacking the account "
    "on next login.",
    remediation="chown <user>:<user> <home-dir>  # for each reported mismatch",
)
def check_home_dirs_owned_by_user() -> CheckResult:
    import pwd

    entries = _passwd_entries()
    if entries is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd could not be read.")
    interactive = _interactive_users(entries)
    mismatched = []
    checked = 0
    for e in interactive:
        if not os.path.isdir(e["home"]):
            continue
        checked += 1
        try:
            st = os.stat(e["home"])
        except (FileNotFoundError, PermissionError):
            continue
        try:
            owner_name = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner_name = str(st.st_uid)
        if owner_name != e["name"]:
            mismatched.append(f"{e['home']} owned by {owner_name}, expected {e['name']}")
    evidence = f"Checked {checked} existing home director(ies)."
    if not mismatched:
        return CheckResult(Status.PASS, evidence + " All correctly owned.")
    return CheckResult(Status.FAIL, evidence + f" Mismatches: {'; '.join(mismatched)}")


@register(
    id="CIS-6.2.14",
    title="The shadow group has no members",
    category=CATEGORY,
    rationale="Members of the 'shadow' group can read /etc/shadow directly, "
    "which is equivalent to root-level access to every account's password "
    "hash - this group should stay empty on a hardened system.",
    remediation="gpasswd -d <user> shadow  # for each unexpected member",
)
def check_shadow_group_empty() -> CheckResult:
    entries = _group_entries()
    if entries is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/group could not be read.")
    for e in entries:
        if e["name"] == "shadow":
            members = [m for m in e["members"].split(",") if m]
            evidence = f"shadow group members: {members or '(none)'}"
            if not members:
                return CheckResult(Status.PASS, evidence)
            return CheckResult(Status.FAIL, evidence)
    return CheckResult(Status.NOT_APPLICABLE, "No 'shadow' group entry found in /etc/group.")


@register(
    id="CIS-6.2.15",
    title="Every group referenced in /etc/passwd exists in /etc/group",
    category=CATEGORY,
    rationale="A passwd entry pointing at a GID with no corresponding group "
    "is usually a leftover from a deleted group - if that GID gets reused "
    "later, the old account unexpectedly regains whatever access the new "
    "group carries.",
    remediation="Create the missing group (groupadd -g <gid> <name>) or reassign the "
    "affected user(s) to a valid group with usermod -g.",
)
def check_passwd_gids_exist_in_group() -> CheckResult:
    passwd_entries = _passwd_entries()
    group_entries = _group_entries()
    if passwd_entries is None or group_entries is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd or /etc/group could not be read.")
    known_gids = {g["gid"] for g in group_entries}
    orphaned = [f"{e['name']} (gid={e['gid']})" for e in passwd_entries if e["gid"] not in known_gids]
    evidence = f"Checked {len(passwd_entries)} /etc/passwd entries against {len(known_gids)} known GIDs."
    if not orphaned:
        return CheckResult(Status.PASS, evidence + " All primary GIDs resolve to a real group.")
    return CheckResult(Status.FAIL, evidence + f" Orphaned: {', '.join(orphaned)}")


def _no_legacy_plus_entries_check(id: str, path: str) -> None:
    @register(
        id=id,
        title=f"No legacy NIS '+' entries exist in {path}",
        category=CATEGORY,
        rationale=f"A line starting with '+' in {path} is a legacy NIS "
        "include directive; if NIS isn't in use (or is misconfigured), it "
        "can leave an unauthenticated wildcard entry that grants unintended "
        "access.",
        remediation=f"Remove any line starting with '+' from {path}.",
    )
    def _check() -> CheckResult:
        lines = read_lines(path)
        if lines is None:
            return CheckResult(Status.NOT_APPLICABLE, f"{path} could not be read.")
        offending = [line for line in lines if line.strip().startswith("+")]
        evidence = f"Checked {len(lines)} line(s) in {path}."
        if not offending:
            return CheckResult(Status.PASS, evidence + " No '+' entries found.")
        return CheckResult(Status.FAIL, evidence + f" Found: {offending}")

    _check.__name__ = f"check_{id.replace('-', '_').replace('.', '_')}"


_no_legacy_plus_entries_check("CIS-6.2.16", "/etc/passwd")
_no_legacy_plus_entries_check("CIS-6.2.17", "/etc/shadow")
_no_legacy_plus_entries_check("CIS-6.2.18", "/etc/group")


@register(
    id="CIS-5.4.3",
    title="The system default password hashing algorithm is SHA-512",
    category=CATEGORY,
    rationale="Weaker legacy hashing algorithms (DES, MD5) are fast to "
    "compute, which makes offline brute-force/dictionary attacks against a "
    "stolen /etc/shadow dramatically cheaper - SHA-512 (and PAM's rounds "
    "tuning) is deliberately slow to compute.",
    remediation="Set 'ENCRYPT_METHOD SHA512' in /etc/login.defs, and ensure "
    "pam_unix.so in /etc/pam.d/common-password uses sha512.",
)
def check_password_hash_algorithm() -> CheckResult:
    lines = read_lines("/etc/login.defs")
    if lines is not None:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) == 2 and parts[0] == "ENCRYPT_METHOD":
                evidence = f"/etc/login.defs ENCRYPT_METHOD {parts[1]}"
                if parts[1].upper() == "SHA512":
                    return CheckResult(Status.PASS, evidence)
                return CheckResult(Status.FAIL, evidence + " (expected SHA512)")
    text = read_text("/etc/pam.d/common-password")
    if text is not None and "sha512" in text:
        return CheckResult(Status.PASS, "/etc/pam.d/common-password references pam_unix.so with sha512.")
    return CheckResult(
        Status.NOT_APPLICABLE,
        "No ENCRYPT_METHOD in /etc/login.defs and no readable /etc/pam.d/common-password "
        "referencing sha512 - could not determine the configured hashing algorithm.",
    )


@register(
    id="CIS-5.4.5",
    title="A default account inactivity lock period is configured",
    category=CATEGORY,
    rationale="Without a default INACTIVE period, an account whose password "
    "has expired stays enabled indefinitely instead of being automatically "
    "locked - useful for catching accounts nobody remembered to "
    "deprovision.",
    remediation="Set 'INACTIVE=30' in /etc/default/useradd (existing accounts also need: "
    "chage --inactive 30 <user>)",
)
def check_default_inactive_lock() -> CheckResult:
    text = read_text("/etc/default/useradd")
    if text is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/default/useradd could not be read.")
    value = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("INACTIVE="):
            value = stripped.split("=", 1)[1]
            break
    evidence = f"/etc/default/useradd INACTIVE={value!r}"
    try:
        if value is not None and int(value) >= 0 and int(value) != -1:
            return CheckResult(Status.PASS, evidence)
    except ValueError:
        pass
    return CheckResult(Status.FAIL, evidence + " (expected INACTIVE set to a value >= 0)")
