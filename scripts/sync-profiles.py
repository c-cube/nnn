#!/usr/bin/env python3
"""Extract greywall Go profiles to JSON files.

Usage: python3 scripts/sync-profiles.py [go_profiles_dir] [output_dir]

Defaults:
  go_profiles_dir = vendor/greywall/internal/profiles
  output_dir      = profiles
"""

import json
import os
import re
import sys
from pathlib import Path


def extract_string_list(text: str) -> list[str]:
    """Extract quoted strings from a Go []string{...} literal."""
    return re.findall(r'"([^"]*)"', text)


def strip_darwin_blocks(text: str) -> str:
    """Remove `if runtime.GOOS == "darwin" { ... }` blocks."""
    result = []
    depth = 0
    in_darwin = False
    i = 0
    while i < len(text):
        # Detect start of darwin block
        if not in_darwin and i < len(text) - 30:
            ahead = text[i:i+80]
            if re.match(r'if\s+runtime\.GOOS\s*==\s*"darwin"', ahead):
                in_darwin = True
                # Skip to the opening brace
                brace_pos = text.find('{', i)
                if brace_pos == -1:
                    break
                depth = 1
                i = brace_pos + 1
                continue

        if in_darwin:
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    in_darwin = False
                    i += 1
                    continue
            i += 1
            continue

        result.append(text[i])
        i += 1

    return ''.join(result)


def parse_profile_file(filepath: Path) -> dict | None:
    """Parse a single Go profile file and return a profile dict."""
    text = filepath.read_text()

    # Strip darwin-specific code
    text = strip_darwin_blocks(text)

    # Extract Names
    names_match = re.search(r'Names:\s*\[\]string\{([^}]*)\}', text)
    if not names_match:
        return None
    names = extract_string_list(names_match.group(1))
    if not names:
        return None

    # Detect toolchain
    toolchain = bool(re.search(r'Toolchain:\s*true', text))

    # Extract filesystem fields — handle both inline and variable-building patterns
    allow_read = extract_field(text, 'AllowRead', 'allowRead')
    allow_write = extract_field(text, 'AllowWrite', 'allowWrite')
    deny_read = extract_field(text, 'DenyRead', 'denyRead')
    deny_write = extract_field(text, 'DenyWrite', 'denyWrite')

    # Extract command fields
    cmd_deny = extract_field(text, 'Deny', 'deny', section='Command')
    cmd_allow = extract_field(text, 'Allow', 'allow', section='Command')
    use_defaults = None
    ud_match = re.search(r'UseDefaults:\s*&(\w+)', text)
    if ud_match:
        use_defaults = ud_match.group(1) == 'useDefaults' or ud_match.group(1) == 'true'
    # Also check for direct bool assignment
    ud_match2 = re.search(r'useDefaults\s*:=\s*(true|false)', text)
    if ud_match2:
        use_defaults = ud_match2.group(1) == 'true'

    profile = {
        'names': names,
        'toolchain': toolchain,
        'filesystem': {
            'allowRead': allow_read,
            'allowWrite': allow_write,
            'denyRead': deny_read,
            'denyWrite': deny_write,
        },
        'command': {
            'deny': cmd_deny,
            'allow': cmd_allow,
        },
    }
    if use_defaults is not None:
        profile['command']['useDefaults'] = use_defaults

    return profile


def extract_field(text: str, go_name: str, json_name: str, section: str = 'Filesystem') -> list[str]:
    """Extract a string list field, handling both inline and variable patterns."""
    # Pattern 1: Inline — FieldName: []string{...}
    pattern = rf'{go_name}:\s*\[\]string\{{([^}}]*)\}}'
    match = re.search(pattern, text)
    if match:
        return extract_string_list(match.group(1))

    # Pattern 2: Variable assignment — fieldName := []string{...} (possibly multiline)
    # The variable name is the camelCase version
    var_name = json_name
    # Find variable assignment with possibly multi-line content
    var_pattern = rf'{var_name}\s*:=\s*\[\]string\{{(.*?)\}}'
    match = re.search(var_pattern, text, re.DOTALL)
    if match:
        return extract_string_list(match.group(1))

    return []


def parse_base_profile(filepath: Path) -> dict | None:
    """Parse base.go which has a different structure."""
    text = filepath.read_text()
    text = strip_darwin_blocks(text)

    allow_read = []
    allow_write = []
    deny_read = []
    deny_write = []

    # base.go uses variable-building pattern for allowRead/allowWrite
    for var_name, target in [('allowRead', allow_read), ('allowWrite', allow_write)]:
        match = re.search(rf'{var_name}\s*:=\s*\[\]string\{{(.*?)\}}', text, re.DOTALL)
        if match:
            target.extend(extract_string_list(match.group(1)))

    # DenyRead and DenyWrite are inline in the config struct
    dr_match = re.search(r'DenyRead:\s*\[\]string\{([^}]*)\}', text)
    if dr_match:
        deny_read = extract_string_list(dr_match.group(1))

    dw_match = re.search(r'DenyWrite:\s*\[\]string\{([^}]*)\}', text)
    if dw_match:
        deny_write = extract_string_list(dw_match.group(1))

    # UseDefaults
    use_defaults = None
    ud_match = re.search(r'useDefaults\s*:=\s*(true|false)', text)
    if ud_match:
        use_defaults = ud_match.group(1) == 'true'

    profile = {
        'names': ['_base'],
        'toolchain': False,
        'filesystem': {
            'allowRead': allow_read,
            'allowWrite': allow_write,
            'denyRead': deny_read,
            'denyWrite': deny_write,
        },
        'command': {
            'deny': [],
            'allow': [],
        },
    }
    if use_defaults is not None:
        profile['command']['useDefaults'] = use_defaults

    return profile


def main():
    go_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('vendor/greywall/internal/profiles')
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('profiles')

    if not go_dir.exists():
        print(f'Error: {go_dir} not found. Did you init the submodule?', file=sys.stderr)
        sys.exit(1)

    # Create output dirs
    (out_dir / 'agents').mkdir(parents=True, exist_ok=True)
    (out_dir / 'toolchains').mkdir(parents=True, exist_ok=True)

    count = 0

    # Parse base profile
    base_path = go_dir / 'base.go'
    if base_path.exists():
        profile = parse_base_profile(base_path)
        if profile:
            out_path = out_dir / 'base.json'
            out_path.write_text(json.dumps(profile, indent=2) + '\n')
            print(f'  {out_path}: {profile["names"]}')
            count += 1

    # Parse agent profiles
    agents_dir = go_dir / 'agents'
    if agents_dir.exists():
        for f in sorted(agents_dir.glob('*.go')):
            if f.name.endswith('_test.go'):
                continue
            profile = parse_profile_file(f)
            if profile:
                name = profile['names'][0]
                out_path = out_dir / 'agents' / f'{name}.json'
                out_path.write_text(json.dumps(profile, indent=2) + '\n')
                print(f'  {out_path}: {profile["names"]}')
                count += 1

    # Parse toolchain profiles
    toolchains_dir = go_dir / 'toolchains'
    if toolchains_dir.exists():
        for f in sorted(toolchains_dir.glob('*.go')):
            if f.name.endswith('_test.go'):
                continue
            profile = parse_profile_file(f)
            if profile:
                name = profile['names'][0]
                out_path = out_dir / 'toolchains' / f'{name}.json'
                out_path.write_text(json.dumps(profile, indent=2) + '\n')
                print(f'  {out_path}: {profile["names"]}')
                count += 1

    print(f'Synced {count} profiles.')


if __name__ == '__main__':
    main()
