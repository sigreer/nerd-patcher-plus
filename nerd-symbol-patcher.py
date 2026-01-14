#!/usr/bin/env python3
"""
Nerd Font Symbol Patcher

Add icons from multiple providers (Simple Icons, Lucide, Material Design, Bootstrap)
or local SVGs to Nerd Fonts.

Usage:
    nerd -i vivaldi                       # Search all providers (simple->lucide->material->bootstrap)
    nerd -i vivaldi -p simple             # Search only Simple Icons
    nerd -i home -p lucide,bootstrap      # Search Lucide first, then Bootstrap
    nerd -i home -p lu                    # Use alias 'lu' for Lucide
    nerd -x viv                           # Search remote providers for 'viv'
    nerd -x viv -p material,simple        # Search only specified providers
    nerd -i ./icons/*                     # Add all SVGs in directory (with confirmation)
    nerd -i ./icons/* -y                  # Add all SVGs without confirmation
    nerd -i ./icon.svg -n custom-name     # Custom name for single icon
    nerd -i ./icon.svg                    # Patch with local SVG (auto-detected)
    nerd -i ./new.svg -u myicon           # Update existing symbol by name
    nerd -l                               # List all patched symbols
    nerd -l -j                            # List symbols in JSON format
    nerd -s cloud                         # Search local symbols by name
    nerd -R myicon                        # Remove 'myicon' from all font files
    nerd --rename old-name new-name       # Rename a symbol

Provider aliases:
    simple: simpleicons, simple-icons, si
    lucide: lu
    material: mdi, materialdesign, material-design
    bootstrap: bi, bootstrap-icons
"""

import argparse
import json
import os
import subprocess
import sys
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

try:
    import fontforge
    import psMat
except ImportError:
    print("Error: fontforge module not found.", file=sys.stderr)
    print("Install with: sudo pacman -S fontforge", file=sys.stderr)
    sys.exit(1)


@contextmanager
def suppress_fontforge_output():
    """Suppress fontforge's stdout/stderr output to prevent terminal crashes.

    fontforge can output problematic characters when reading/writing fonts,
    particularly when dealing with PUA (Private Use Area) glyphs.
    """
    # Save original file descriptors
    stdout_fd = sys.stdout.fileno()
    stderr_fd = sys.stderr.fileno()
    saved_stdout = os.dup(stdout_fd)
    saved_stderr = os.dup(stderr_fd)

    try:
        # Open /dev/null and redirect stdout/stderr to it
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stdout_fd)
        os.dup2(devnull, stderr_fd)
        os.close(devnull)
        yield
    finally:
        # Restore original file descriptors
        os.dup2(saved_stdout, stdout_fd)
        os.dup2(saved_stderr, stderr_fd)
        os.close(saved_stdout)
        os.close(saved_stderr)


# Constants
FONT_DIR_USER = Path.home() / ".local/share/fonts/NerdFontsSymbolsOnly"
ICON_LOG_FILE = FONT_DIR_USER / "patched-icons-log.txt"

# Icon providers configuration
PROVIDERS = {
    "simple": {
        "url": "https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/{name}.svg",
        "list_url": "https://api.github.com/repos/simple-icons/simple-icons/contents/icons",
        "aliases": ["simpleicons", "simple-icons", "si"],
    },
    "lucide": {
        "url": "https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/{name}.svg",
        "list_url": "https://api.github.com/repos/lucide-icons/lucide/contents/icons",
        "aliases": ["lu"],
    },
    "material": {
        "url": "https://raw.githubusercontent.com/Templarian/MaterialDesign/master/svg/{name}.svg",
        "list_url": "https://api.github.com/repos/Templarian/MaterialDesign/contents/svg",
        "aliases": ["mdi", "materialdesign", "material-design"],
    },
    "bootstrap": {
        "url": "https://raw.githubusercontent.com/twbs/icons/main/icons/{name}.svg",
        "list_url": "https://api.github.com/repos/twbs/icons/contents/icons",
        "aliases": ["bi", "bootstrap-icons"],
    },
}
DEFAULT_PROVIDER_ORDER = ["simple", "lucide", "material", "bootstrap"]

# Colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"


def print_info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}", file=sys.stderr)


def print_success(msg):
    print(f"{GREEN}[SUCCESS]{NC} {msg}", file=sys.stderr)


def print_warning(msg):
    print(f"{YELLOW}[WARNING]{NC} {msg}", file=sys.stderr)


def print_error(msg):
    print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)


def resolve_provider_name(name: str) -> str | None:
    """Resolve provider alias to canonical name. Returns None if not found."""
    name_lower = name.lower().replace("_", "-")
    for provider, config in PROVIDERS.items():
        if name_lower == provider or name_lower in config["aliases"]:
            return provider
    return None


def parse_providers(provider_string: str) -> list[str]:
    """Parse comma-separated provider names/aliases to canonical names.

    Raises ValueError if any provider name is invalid.
    """
    providers = []
    for name in provider_string.split(","):
        name = name.strip()
        if not name:
            continue
        resolved = resolve_provider_name(name)
        if resolved is None:
            valid = ", ".join(PROVIDERS.keys())
            raise ValueError(f"Unknown provider '{name}'. Valid providers: {valid}")
        if resolved not in providers:
            providers.append(resolved)
    return providers


def classify_icon_input(name: str, providers_specified: bool = False) -> tuple[str, bool]:
    """Classify input as local file or remote icon name.

    Returns (name, is_local) where is_local=True means local file path.
    Raises FileNotFoundError if looks like local file but doesn't exist.
    Raises ValueError if file is not an SVG or if local path used with providers.

    Detection: Any input containing '.', '/', or wildcards is treated as a local file path.
    """
    name = name.strip()

    # Check if it looks like a file path (contains '.', '/', or wildcards)
    if '.' in name or '/' in name or '*' in name or '?' in name:
        if providers_specified:
            raise ValueError(f"Local paths not allowed with -p/--providers: {name}")

        # For wildcards, don't check existence yet (glob will handle it)
        if '*' in name or '?' in name:
            return (name, True)

        path = Path(name)
        if not path.exists():
            raise FileNotFoundError(f"Local file not found: {name}")
        if path.suffix.lower() != '.svg':
            raise ValueError(f"File is not an SVG: {name}")
        return (name, True)

    # No special chars = remote icon name
    return (name, False)


def is_safe_to_render_glyphs() -> tuple[bool, str]:
    """Check if it's safe to render custom glyphs in terminal.

    Returns (is_safe, reason_message).

    Logic:
    1. Get font file modification time
    2. Check if running in Ghostty (GHOSTTY_BIN_DIR env var)
    3. If in Ghostty, find oldest Ghostty process start time
    4. Compare: safe if oldest Ghostty started AFTER font was modified
    """
    font_file = FONT_DIR_USER / "SymbolsNerdFont-Regular.ttf"
    if not font_file.exists():
        return (False, "Font file not found")

    font_mtime = font_file.stat().st_mtime

    # Check if we're in Ghostty
    if 'GHOSTTY_BIN_DIR' not in os.environ:
        return (True, "Not running in Ghostty")

    # Find all Ghostty processes
    try:
        result = subprocess.run(['pgrep', 'ghostty'],
                                capture_output=True, text=True)
        if result.returncode != 0:
            return (True, "No Ghostty processes found")

        pids = result.stdout.strip().split('\n')
        oldest_start = float('inf')

        for pid in pids:
            if not pid:
                continue
            proc_path = Path(f'/proc/{pid}')
            if proc_path.exists():
                # Use /proc/<pid> directory creation time as process start time
                start_time = proc_path.stat().st_mtime
                oldest_start = min(oldest_start, start_time)

        if oldest_start == float('inf'):
            return (True, "Could not determine Ghostty start time")

        if oldest_start > font_mtime:
            return (True, "Ghostty started after font update")
        else:
            return (False, "Ghostty started before font update - restart terminal to see glyphs")

    except Exception as e:
        return (False, f"Could not determine Ghostty status: {e}")


def get_js_escape(codepoint: int) -> str:
    """Generate JavaScript/GJS escape sequence for a Unicode codepoint."""
    if codepoint > 0xFFFF:
        # Supplementary plane - use surrogate pairs
        high = 0xD800 + ((codepoint - 0x10000) >> 10)
        low = 0xDC00 + ((codepoint - 0x10000) & 0x3FF)
        return f"\\u{high:04x}\\u{low:04x}"
    return f"\\u{codepoint:04x}"


def expand_wildcard_paths(pattern: str) -> list[Path]:
    """Expand wildcard pattern to matching SVG files."""
    if '*' in pattern or '?' in pattern:
        # Handle relative paths
        if pattern.startswith('./') or pattern.startswith('../'):
            base = Path('.')
            glob_pattern = pattern
        elif pattern.startswith('/'):
            # Absolute path - extract base and pattern
            parts = pattern.split('/')
            # Find first part with wildcard
            for i, part in enumerate(parts):
                if '*' in part or '?' in part:
                    base = Path('/'.join(parts[:i])) if i > 0 else Path('/')
                    glob_pattern = '/'.join(parts[i:])
                    break
            else:
                base = Path('.')
                glob_pattern = pattern
        else:
            base = Path('.')
            glob_pattern = pattern

        matches = sorted(base.glob(glob_pattern))
        return [m for m in matches if m.is_file() and m.suffix.lower() == '.svg']
    return []


def confirm_wildcard_patch(files: list[Path], skip_confirm: bool = False) -> bool:
    """Prompt user to confirm patching wildcard-matched files."""
    if skip_confirm:
        return True

    print_info(f"Found {len(files)} SVG file(s) matching pattern:")
    for f in files[:10]:  # Show first 10
        print_info(f"  - {f.name}")
    if len(files) > 10:
        print_info(f"  ... and {len(files) - 10} more")

    try:
        response = input(f"\nPatch all {len(files)} icons? [y/N]: ").strip().lower()
        return response in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return False


def search_remote_icons(query: str, providers: list[str] | None = None, output_json: bool = False) -> int:
    """Search for icons matching query across remote providers.

    Uses GitHub Trees API to get complete file lists (contents API is limited to 1000 items).
    Returns exit code (0 for success, 1 for no matches found).
    """
    import urllib.request

    search_providers = providers or DEFAULT_PROVIDER_ORDER
    results = {}

    # Trees API URLs for complete file listings
    PROVIDER_TREES = {
        "simple": ("https://api.github.com/repos/simple-icons/simple-icons/git/trees/develop?recursive=1", "icons/"),
        "lucide": ("https://api.github.com/repos/lucide-icons/lucide/git/trees/main?recursive=1", "icons/"),
        "material": ("https://api.github.com/repos/Templarian/MaterialDesign/git/trees/master?recursive=1", "svg/"),
        "bootstrap": ("https://api.github.com/repos/twbs/icons/git/trees/main?recursive=1", "icons/"),
    }

    print_info(f"Searching for '{query}' across providers: {', '.join(search_providers)}")

    for provider in search_providers:
        try:
            tree_url, icon_prefix = PROVIDER_TREES[provider]
            req = urllib.request.Request(tree_url)
            req.add_header("User-Agent", "nerd-symbol-patcher/1.0")
            with urlopen(req, timeout=30) as response:
                data = json.loads(response.read())

            matches = []
            query_lower = query.lower()
            for item in data.get("tree", []):
                path = item.get("path", "")
                # Only look at SVG files in the icons directory
                if path.startswith(icon_prefix) and path.endswith(".svg"):
                    # Extract icon name from path like "icons/github.svg" -> "github"
                    icon_name = path[len(icon_prefix):-4]
                    if query_lower in icon_name.lower():
                        matches.append(icon_name)

            if matches:
                results[provider] = sorted(matches)
        except Exception as e:
            print_warning(f"Could not search {provider}: {e}")

    if not results:
        if output_json:
            print(json.dumps({"query": query, "providers": search_providers, "results": {}, "total": 0}))
        else:
            print_error(f"No icons found matching '{query}'")
        return 1

    # Output results
    if output_json:
        total = sum(len(icons) for icons in results.values())
        print(json.dumps({
            "query": query,
            "providers": list(results.keys()),
            "results": results,
            "total": total
        }, indent=2))
    else:
        print("", file=sys.stderr)
        for provider, icons in results.items():
            print_success(f"{provider.upper()} ({len(icons)} matches):")
            for icon in icons[:20]:  # Limit display
                print(f"  {icon}", file=sys.stderr)
            if len(icons) > 20:
                print(f"  ... and {len(icons) - 20} more", file=sys.stderr)
            print("", file=sys.stderr)

    return 0


def download_icon_from_providers(
    icon_name: str,
    dest_dir: Path,
    providers: list[str] | None = None,
    custom_name: str | None = None
) -> tuple[bool, str | None]:
    """Download icon from providers in order.

    Returns (success, error_message).
    """
    search_providers = providers or DEFAULT_PROVIDER_ORDER
    dest_name = custom_name or icon_name
    dest = dest_dir / f"{dest_name}.svg"

    for provider in search_providers:
        url = PROVIDERS[provider]["url"].format(name=icon_name)
        try:
            with urlopen(url, timeout=10) as response:
                dest.write_bytes(response.read())
            print_success(f"  Downloaded {icon_name} from {provider}" + (f" as '{dest_name}'" if custom_name else ""))
            return (True, None)
        except (URLError, HTTPError):
            continue  # Try next provider

    return (False, f"Not found in: {', '.join(search_providers)}")


def list_symbols(show_all_formats: bool = False, output_json: bool = False, search_query: str | None = None):
    """List all custom symbols (sgc_*) in installed Nerd Fonts.

    Args:
        show_all_formats: Show all encoding formats (Unicode, UTF-8 hex, JS/GJS escape)
        output_json: Output results in JSON format
        search_query: Optional substring to filter symbols by name
    """
    font_file = FONT_DIR_USER / "SymbolsNerdFont-Regular.ttf"

    if not font_file.exists():
        if output_json:
            print(json.dumps({"error": "Patched font not found", "font_path": str(font_file)}))
            return 1
        print_error(f"Patched font not found: {font_file}")
        print_info("Run the script with -i flag to patch fonts first")
        return 1

    # Check if it's safe to render glyphs
    safe_to_render, safety_reason = is_safe_to_render_glyphs()

    if not output_json:
        if search_query:
            print_info(f"Searching for symbols matching '{search_query}'")
        else:
            print_info("Scanning for custom symbols (sgc_*)")
        print_info("=" * 42)
        print_success(f"Reading: {font_file.name}")
        print_info(f"Location: {font_file}")
        print("", file=sys.stderr)

    try:
        # Suppress fontforge output during font operations
        with suppress_fontforge_output():
            font = fontforge.open(str(font_file))

            icons = []
            for glyph in font.glyphs():
                if glyph.glyphname and glyph.glyphname.startswith("sgc_"):
                    icon_name = glyph.glyphname.replace("sgc_", "")
                    codepoint = glyph.encoding
                    if codepoint >= 0:
                        # Apply search filter if provided
                        if search_query is None or search_query.lower() in icon_name.lower():
                            icons.append((icon_name, codepoint))

            font.close()

        if not icons:
            if output_json:
                print(json.dumps({
                    "symbols": [],
                    "count": 0,
                    "font_path": str(font_file),
                    "safe_to_render": safe_to_render,
                    "search_query": search_query
                }))
                return 0
            if search_query:
                print(f"No symbols found matching '{search_query}'.", file=sys.stderr)
            else:
                print("No custom symbols found in this font.", file=sys.stderr)
            return 0

        icons.sort(key=lambda x: x[0])

        # JSON output mode
        if output_json:
            symbols = []
            for icon_name, codepoint in icons:
                char = chr(codepoint)
                symbols.append({
                    "name": icon_name,
                    "glyph_name": f"sgc_{icon_name}",
                    "codepoint": codepoint,
                    "unicode": f"U+{codepoint:04X}",
                    "utf8_hex": char.encode("utf-8").hex(),
                    "js_escape": get_js_escape(codepoint)
                })

            result = {
                "symbols": symbols,
                "count": len(symbols),
                "font_path": str(font_file),
                "safe_to_render": safe_to_render
            }
            if search_query:
                result["search_query"] = search_query

            print(json.dumps(result, indent=2))
            return 0

        # Human-readable output mode
        print(f"Found {len(icons)} custom symbol(s):\n", file=sys.stderr)

        # Show safety warning if glyphs won't render correctly
        if not safe_to_render:
            print_warning(f"Glyph rendering disabled: {safety_reason}")
            print_info("Showing escape codes only. Restart your terminal to see glyphs.")
            print("", file=sys.stderr)

        if show_all_formats:
            if safe_to_render:
                print(f"{'Icon Name':<25} {'Unicode':<12} {'Glyph':<8} {'UTF-8 Hex':<15} {'JS/GJS Escape'}", file=sys.stderr)
                print("-" * 90, file=sys.stderr)
                for icon_name, codepoint in icons:
                    char = chr(codepoint)
                    utf8_hex = char.encode("utf-8").hex()
                    js_escape = get_js_escape(codepoint)
                    print(f"{icon_name:<25} U+{codepoint:04X}      {char:<8} {utf8_hex:<15} {js_escape}", file=sys.stderr)
            else:
                print(f"{'Icon Name':<25} {'Unicode':<12} {'UTF-8 Hex':<15} {'JS/GJS Escape'}", file=sys.stderr)
                print("-" * 82, file=sys.stderr)
                for icon_name, codepoint in icons:
                    char = chr(codepoint)
                    utf8_hex = char.encode("utf-8").hex()
                    js_escape = get_js_escape(codepoint)
                    print(f"{icon_name:<25} U+{codepoint:04X}      {utf8_hex:<15} {js_escape}", file=sys.stderr)
        else:
            if safe_to_render:
                print(f"{'Icon Name':<25} {'Glyph':<8} {'Escape'}", file=sys.stderr)
                print("-" * 50, file=sys.stderr)
                for icon_name, codepoint in icons:
                    char = chr(codepoint)
                    escape = f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
                    print(f"{icon_name:<25} {char:<8} {escape}", file=sys.stderr)
            else:
                print(f"{'Icon Name':<25} {'Escape'}", file=sys.stderr)
                print("-" * 42, file=sys.stderr)
                for icon_name, codepoint in icons:
                    escape = f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
                    print(f"{icon_name:<25} {escape}", file=sys.stderr)

        return 0

    except Exception as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
            return 1
        print_error(f"Error reading font: {e}")
        return 1


def test_font(font_path: str):
    """Display all Simple Icons in a patched font file."""
    if not os.path.exists(font_path):
        print_error(f"Font file not found: {font_path}")
        return 1

    print_info(f"Scanning font for Simple Icons: {font_path}")
    print_info("=" * 42)

    try:
        # Suppress fontforge output during font operations
        with suppress_fontforge_output():
            font = fontforge.open(font_path)

            icons = []
            for glyph in font.glyphs():
                if glyph.glyphname and glyph.glyphname.startswith("sgc_"):
                    icon_name = glyph.glyphname.replace("sgc_", "")
                    codepoint = glyph.encoding
                    if codepoint >= 0:
                        icons.append((icon_name, codepoint))

            font.close()

        if not icons:
            print("No Simple Icons found in this font.")
            return 0

        icons.sort(key=lambda x: x[0])

        print(f"\nFound {len(icons)} Simple Icon(s):\n")
        print(f"{'Icon Name':<25} {'Unicode':<12} {'Glyph':<8} {'UTF-8 Hex':<15} {'JS/GJS Escape':<20} {'Test Commands'}")
        print("-" * 120)

        for icon_name, codepoint in icons:
            char = chr(codepoint)
            utf8_hex = char.encode("utf-8").hex()
            utf8_bytes = [utf8_hex[i : i + 2] for i in range(0, len(utf8_hex), 2)]
            utf8_printf = "\\x" + "\\x".join(utf8_bytes)
            js_escape = get_js_escape(codepoint)
            print(f"{icon_name:<25} U+{codepoint:04X}      {char:<8} {utf8_hex:<15} {js_escape:<20} printf '{utf8_printf}'")

        return 0

    except Exception as e:
        print_error(f"Error reading font: {e}")
        return 1


def parse_symbol_reference(ref: str) -> tuple[str | None, int | None]:
    """Parse a symbol reference string into name or codepoint.

    Returns (name, None) for name references or (None, codepoint) for codepoint references.

    Codepoint format: starts with 'u' or 'U' followed by 4-8 hex digits.

    Examples:
        'myicon' -> ('myicon', None)
        'ue069' -> (None, 0xe069)
        'UE069' -> (None, 0xe069)
        'Uf0001' -> (None, 0xf0001)
        'U000f0001' -> (None, 0xf0001)
    """
    ref = ref.strip()

    # Check for codepoint format: u/U followed by 4-8 hex digits
    if len(ref) >= 5 and ref[0].lower() == 'u':
        hex_part = ref[1:]
        # Validate hex digits and length (4-8 characters)
        if len(hex_part) >= 4 and len(hex_part) <= 8 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
            try:
                codepoint = int(hex_part, 16)
                return (None, codepoint)
            except ValueError:
                pass  # Fall through to treat as name

    # Otherwise treat as a name
    return (ref, None)


def update_symbol(ref: str, svg_path: Path):
    """Update a specific symbol in all installed Nerd Font files.

    Args:
        ref: Symbol reference (name like 'myicon' or codepoint like '\\ue069')
        svg_path: Path to the SVG file to use for the update
    """
    print_info(f"Updating symbol: {ref}")
    print_info("=" * 42)

    # Parse the reference
    name, codepoint = parse_symbol_reference(ref)
    if name is None and codepoint is None:
        return 1

    if not FONT_DIR_USER.exists():
        print_error(f"Font directory not found: {FONT_DIR_USER}")
        return 1

    if not svg_path.exists():
        print_error(f"SVG file not found: {svg_path}")
        return 1

    # Find all font files
    font_files = list(FONT_DIR_USER.glob("*.ttf")) + list(FONT_DIR_USER.glob("*.otf"))
    if not font_files:
        print_error("No font files found")
        return 1

    updated_count = 0
    target_glyph_name = f"sgc_{name}" if name else None

    for font_file in font_files:
        try:
            with suppress_fontforge_output():
                font = fontforge.open(str(font_file))

            # Find the target glyph
            found_glyph = None
            for glyph in font.glyphs():
                if name and glyph.glyphname == target_glyph_name:
                    found_glyph = glyph
                    break
                elif codepoint and glyph.encoding == codepoint:
                    found_glyph = glyph
                    break

            if not found_glyph:
                if name:
                    print_info(f"  Symbol '{name}' not found in {font_file.name}")
                else:
                    print_info(f"  Codepoint U+{codepoint:04X} not found in {font_file.name}")
                font.close()
                continue

            glyph_cp = found_glyph.encoding
            glyph_name = found_glyph.glyphname

            print_info(f"  Found {glyph_name} at U+{glyph_cp:04X} in {font_file.name}")

            # Clear and reimport the glyph
            found_glyph.clear()
            found_glyph.importOutlines(str(svg_path))

            # Scale and position (same as new glyphs)
            bbox = found_glyph.boundingBox()
            if bbox[2] > bbox[0] and bbox[3] > bbox[1]:
                width = bbox[2] - bbox[0]
                height = bbox[3] - bbox[1]
                scale = min(font.em / width, font.em / height) * 0.8
                found_glyph.transform(psMat.scale(scale))

                bbox_new = found_glyph.boundingBox()
                x_offset = (font.em - (bbox_new[2] - bbox_new[0])) / 2 - bbox_new[0]
                target_bottom = -font.descent * 0.8
                target_top = font.ascent * 0.95
                vertical_center = (target_top + target_bottom) / 2
                icon_center = (bbox_new[3] + bbox_new[1]) / 2
                y_offset = vertical_center - icon_center
                found_glyph.transform(psMat.translate(x_offset, y_offset))
                found_glyph.width = int(font.em)

            with suppress_fontforge_output():
                font.generate(str(font_file))

            print_success(f"  Updated in {font_file.name}")
            updated_count += 1

            font.close()

        except Exception as e:
            print_error(f"  Error processing {font_file.name}: {e}")

    print("", file=sys.stderr)
    if updated_count > 0:
        print_success(f"Updated symbol in {updated_count} font file(s)")
        print_info("Refreshing font cache...")
        os.system(f"fc-cache -f '{FONT_DIR_USER}'")

        # Display the updated symbol info
        display_name = name if name else f"U+{codepoint:04X}"
        print_info(f"Updated symbol: {display_name}")
        print_warning("NOTE: Restart your terminal/applications to see changes")
    else:
        if name:
            print_warning(f"Symbol '{name}' was not found in any font files")
        else:
            print_warning(f"Codepoint U+{codepoint:04X} was not found in any font files")

    return 0


def remove_symbol(icon_name: str):
    """Remove a custom symbol from all installed Nerd Font files."""
    print_info(f"Removing symbol: {icon_name}")
    print_info("=" * 42)

    if not FONT_DIR_USER.exists():
        print_error(f"Font directory not found: {FONT_DIR_USER}")
        return 1

    # Find all font files
    font_files = list(FONT_DIR_USER.glob("*.ttf")) + list(FONT_DIR_USER.glob("*.otf"))
    if not font_files:
        print_error("No font files found")
        return 1

    glyph_name = f"sgc_{icon_name}"
    removed_count = 0
    found_in = []

    for font_file in font_files:
        try:
            with suppress_fontforge_output():
                font = fontforge.open(str(font_file))

            # Find the glyph
            found = False
            codepoint = None
            for glyph in font.glyphs():
                if glyph.glyphname == glyph_name:
                    found = True
                    codepoint = glyph.encoding
                    # Clear the glyph (remove its outlines)
                    glyph.clear()
                    # Reset the glyph name to indicate it's empty
                    glyph.glyphname = f".notdef_{codepoint:04X}"
                    break

            if found:
                with suppress_fontforge_output():
                    font.generate(str(font_file))
                found_in.append((font_file.name, codepoint))
                removed_count += 1
                print_success(f"  Removed from {font_file.name} (was at U+{codepoint:04X})")
            else:
                print_info(f"  Not found in {font_file.name}")

            font.close()

        except Exception as e:
            print_error(f"  Error processing {font_file.name}: {e}")

    print("", file=sys.stderr)
    if removed_count > 0:
        print_success(f"Removed '{icon_name}' from {removed_count} font file(s)")
        print_info("Refreshing font cache...")
        os.system(f"fc-cache -f '{FONT_DIR_USER}'")
        print_warning("NOTE: Restart your terminal/applications to see changes")
    else:
        print_warning(f"Symbol '{icon_name}' was not found in any font files")

    return 0


def rename_symbol(old_name: str, new_name: str):
    """Rename a custom symbol in all installed Nerd Font files."""
    print_info(f"Renaming symbol: {old_name} -> {new_name}")
    print_info("=" * 42)

    if not FONT_DIR_USER.exists():
        print_error(f"Font directory not found: {FONT_DIR_USER}")
        return 1

    # Find all font files
    font_files = list(FONT_DIR_USER.glob("*.ttf")) + list(FONT_DIR_USER.glob("*.otf"))
    if not font_files:
        print_error("No font files found")
        return 1

    old_glyph_name = f"sgc_{old_name}"
    new_glyph_name = f"sgc_{new_name}"
    renamed_count = 0

    for font_file in font_files:
        try:
            with suppress_fontforge_output():
                font = fontforge.open(str(font_file))

            # Check if new name already exists
            for glyph in font.glyphs():
                if glyph.glyphname == new_glyph_name:
                    print_error(f"  {font_file.name}: '{new_name}' already exists at U+{glyph.encoding:04X}")
                    font.close()
                    continue

            # Find and rename the glyph
            found = False
            for glyph in font.glyphs():
                if glyph.glyphname == old_glyph_name:
                    found = True
                    codepoint = glyph.encoding
                    glyph.glyphname = new_glyph_name
                    with suppress_fontforge_output():
                        font.generate(str(font_file))
                    renamed_count += 1
                    print_success(f"  Renamed in {font_file.name} (U+{codepoint:04X})")
                    break

            if not found:
                print_info(f"  Not found in {font_file.name}")

            font.close()

        except Exception as e:
            print_error(f"  Error processing {font_file.name}: {e}")

    print("", file=sys.stderr)
    if renamed_count > 0:
        print_success(f"Renamed '{old_name}' to '{new_name}' in {renamed_count} font file(s)")
        print_info("Refreshing font cache...")
        os.system(f"fc-cache -f '{FONT_DIR_USER}'")
        print_info(f"New symbol name: {new_name}")
        print_warning("NOTE: Restart your terminal/applications to see changes")
    else:
        print_warning(f"Symbol '{old_name}' was not found in any font files")

    return 0


def download_icons(icon_names: list[str], dest_dir: Path) -> list[str]:
    """Download Simple Icons SVGs. Returns list of failed icon names."""
    failed = []
    print_info("Downloading Simple Icons...")

    for icon in icon_names:
        icon = icon.strip()
        if not icon:
            continue

        url = f"{SIMPLEICONS_BASE_URL}/{icon}.svg"
        dest = dest_dir / f"{icon}.svg"

        print_info(f"  Downloading {icon}.svg...")
        try:
            with urlopen(url) as response:
                dest.write_bytes(response.read())
            print_success(f"    Downloaded {icon}.svg")
        except (URLError, HTTPError) as e:
            print_error(f"    Failed to download {icon}.svg")
            print_warning("    Make sure the icon name is correct (check https://simpleicons.org/)")
            failed.append(f"{icon}.svg (download failed: {e})")

    return failed


def copy_local_svgs(svg_paths: list[str], dest_dir: Path, custom_name: str | None = None) -> list[str]:
    """Copy local SVG files to dest_dir. Returns list of failed paths.

    Args:
        svg_paths: List of local SVG file paths
        dest_dir: Destination directory
        custom_name: Custom name for single icon (only applied if len(svg_paths) == 1)
    """
    failed = []
    print_info("Processing local SVG files...")

    for i, svg_path in enumerate(svg_paths):
        svg_path = svg_path.strip()
        if not svg_path:
            continue

        src = Path(svg_path)

        if not src.exists():
            print_error(f"  Local SVG file not found: {svg_path}")
            failed.append(f"{svg_path} (file not found)")
            continue

        if src.suffix.lower() != ".svg":
            print_error(f"  File is not an SVG: {svg_path}")
            failed.append(f"{svg_path} (not an SVG file)")
            continue

        # Use custom name only for single icon
        icon_name = custom_name if (custom_name and len(svg_paths) == 1) else src.stem
        dest = dest_dir / f"{icon_name}.svg"

        print_info(f"  Copying {src.name} as '{icon_name}'...")
        try:
            shutil.copy(src, dest)
            print_success(f"    Copied {src.name}" + (f" as '{icon_name}'" if custom_name else ""))
        except Exception as e:
            print_error(f"    Failed to copy {src.name}: {e}")
            failed.append(f"{svg_path} (copy failed)")

    return failed


def find_fonts(patterns: list[str]) -> list[Path]:
    """Find matching Nerd Font files."""
    print_info("Searching for matching Nerd Fonts...")

    if not FONT_DIR_USER.exists():
        print_error(f"Font directory not found: {FONT_DIR_USER}")
        return []

    found = []
    for pattern in patterns:
        pattern = pattern.strip().lower()
        for font_file in FONT_DIR_USER.iterdir():
            if font_file.suffix.lower() in (".ttf", ".otf"):
                if pattern in font_file.name.lower():
                    found.append(font_file)

    if not found:
        print_error(f"No matching fonts found for patterns: {patterns}")
        return []

    # Deduplicate
    unique = list(dict.fromkeys(found))

    print_success(f"Found {len(unique)} font file(s)")
    for font in unique:
        print_info(f"  - {font.name}")

    return unique


def patch_font(font_path: Path, icon_dir: Path, output_path: Path, start_codepoint: int | None = None, update: bool = False, duplicate: bool = False):
    """Patch a font with icons from icon_dir. If update=True, overwrite existing glyphs. If duplicate=True, add copies at new codepoints."""
    # Flush output before fontforge operations to prevent interleaving
    sys.stdout.flush()
    sys.stderr.flush()
    print(f"Opening font: {font_path}")
    # Suppress fontforge output during font open to prevent problematic characters
    with suppress_fontforge_output():
        font = fontforge.open(str(font_path))

    # Auto-detect starting codepoint if not specified
    # IMPORTANT: Avoid codepoints where low byte is 0x00-0x1F (ASCII control chars)
    # Some terminals (like Ghostty) may interpret these as control characters
    # Safe low bytes: 0x20-0x7E (printable ASCII) and 0x80-0xFF
    def is_safe_codepoint(cp):
        """Check if codepoint's low byte won't be interpreted as control char."""
        low_byte = cp & 0xFF
        return low_byte >= 0x20  # 0x20 = space, first printable ASCII

    if start_codepoint:
        print(f"Using specified starting codepoint: U+{start_codepoint:04X}")
    else:
        occupied = set()
        for glyph in font.glyphs():
            if 0xE000 <= glyph.encoding <= 0xF8FF:
                occupied.add(glyph.encoding)

        # Start at F600 to avoid conflicts with standard Nerd Font glyphs
        # The E000-F5FF range is heavily populated by Nerd Fonts
        # F600-F7FF is typically empty and still allows single-block \uXXXX escapes
        start_codepoint = 0xF600
        consecutive_free = 0
        for cp in range(0xF600, 0xF900):
            # Skip codepoints with control char low bytes
            if not is_safe_codepoint(cp):
                consecutive_free = 0
                continue
            if cp not in occupied:
                consecutive_free += 1
                if consecutive_free >= 100:
                    start_codepoint = cp - 99
                    break
            else:
                consecutive_free = 0

        if consecutive_free < 100:
            print("Warning: BMP Private Use Area is crowded, using Plane 15 PUA (U+F0000+)")
            start_codepoint = 0xF0000
        else:
            print(f"Auto-detected safe starting codepoint: U+{start_codepoint:04X}")

    # Get icon files
    icon_files = sorted(icon_dir.glob("*.svg"))

    # Check for existing icons
    existing_icons = {}
    for glyph in font.glyphs():
        if glyph.glyphname and glyph.glyphname.startswith("sgc_"):
            icon_name = glyph.glyphname.replace("sgc_", "")
            existing_icons[icon_name] = glyph.encoding
            print(f"  Found existing icon: {icon_name} at U+{glyph.encoding:04X}")

    print(f"Processing {len(icon_files)} icons ({len(existing_icons)} already exist)...")

    mappings = []
    new_mappings = []
    added_count = 0
    updated_count = 0
    skipped_count = 0
    current_cp = start_codepoint

    for icon_file in icon_files:
        icon_name = icon_file.stem

        if icon_name in existing_icons:
            existing_cp = existing_icons[icon_name]
            if duplicate:
                # Add copy at new codepoint (don't modify existing)
                print(f"  Duplicating {icon_name} (exists at U+{existing_cp:04X}, adding copy)")
                # Fall through to add at new codepoint
            elif update:
                # Update existing glyph - clear and reimport
                print(f"  Updating {icon_name} at U+{existing_cp:04X}")
                glyph = font[existing_cp]
                glyph.clear()
                glyph.importOutlines(str(icon_file))

                # Scale and position (same as new glyphs)
                bbox = glyph.boundingBox()
                if bbox[2] > bbox[0] and bbox[3] > bbox[1]:
                    width = bbox[2] - bbox[0]
                    height = bbox[3] - bbox[1]
                    scale = min(font.em / width, font.em / height) * 0.8
                    glyph.transform(psMat.scale(scale))

                    bbox_new = glyph.boundingBox()
                    x_offset = (font.em - (bbox_new[2] - bbox_new[0])) / 2 - bbox_new[0]
                    target_bottom = -font.descent * 0.8
                    target_top = font.ascent * 0.95
                    vertical_center = (target_top + target_bottom) / 2
                    icon_center = (bbox_new[3] + bbox_new[1]) / 2
                    y_offset = vertical_center - icon_center
                    glyph.transform(psMat.translate(x_offset, y_offset))
                    glyph.width = int(font.em)

                mappings.append((icon_name, existing_cp))
                new_mappings.append((icon_name, existing_cp))
                updated_count += 1
                continue
            else:
                print(f"  Skipping {icon_name} (already exists at U+{existing_cp:04X})")
                mappings.append((icon_name, existing_cp))
                skipped_count += 1
                continue

        # Find next available codepoint (skip unsafe ones with control char low bytes)
        max_attempts = 1000
        attempts = 0
        while (current_cp in font or not is_safe_codepoint(current_cp)) and attempts < max_attempts:
            current_cp += 1
            attempts += 1

        if attempts >= max_attempts:
            print(f"  ERROR: Could not find free codepoint for {icon_name}")
            skipped_count += 1
            continue

        codepoint = current_cp
        current_cp += 1

        print(f"  Adding {icon_name} at U+{codepoint:04X}")
        mappings.append((icon_name, codepoint))
        new_mappings.append((icon_name, codepoint))
        added_count += 1

        # Create glyph
        glyph = font.createChar(codepoint, f"sgc_{icon_name}")
        glyph.importOutlines(str(icon_file))

        # Scale and position
        bbox = glyph.boundingBox()
        if bbox[2] > bbox[0] and bbox[3] > bbox[1]:
            width = bbox[2] - bbox[0]
            height = bbox[3] - bbox[1]
            scale = min(font.em / width, font.em / height) * 0.8

            glyph.transform(psMat.scale(scale))

            bbox_new = glyph.boundingBox()
            x_offset = (font.em - (bbox_new[2] - bbox_new[0])) / 2 - bbox_new[0]

            target_bottom = -font.descent * 0.8
            target_top = font.ascent * 0.95
            vertical_center = (target_top + target_bottom) / 2
            icon_center = (bbox_new[3] + bbox_new[1]) / 2
            y_offset = vertical_center - icon_center

            glyph.transform(psMat.translate(x_offset, y_offset))
            glyph.width = int(font.em)

    # Save font
    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Saving patched font to: {output_path}")
    # Suppress fontforge output during font save/close to prevent problematic characters
    with suppress_fontforge_output():
        font.generate(str(output_path))
        font.close()

    print(f"Successfully patched font! (Added: {added_count}, Updated: {updated_count}, Skipped: {skipped_count})")
    # Flush after fontforge operations complete
    sys.stdout.flush()
    sys.stderr.flush()

    return mappings, new_mappings


def install_fonts(output_path: Path):
    """Install patched fonts to user font directory."""
    print_info(f"Installing patched fonts to {FONT_DIR_USER}...")
    FONT_DIR_USER.mkdir(parents=True, exist_ok=True)

    installed = 0
    for font_file in output_path.iterdir():
        if font_file.suffix.lower() in (".ttf", ".otf"):
            dest = FONT_DIR_USER / font_file.name
            shutil.copy(font_file, dest)
            print_success(f"  Installed {font_file.name}")
            installed += 1

    print_info("Refreshing font cache...")
    os.system(f"fc-cache -f '{FONT_DIR_USER}'")
    print_success(f"Installed {installed} font(s)")


def save_to_log(new_mappings: list[tuple[str, int]]):
    """Save newly patched icons to log file."""
    if not new_mappings:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    FONT_DIR_USER.mkdir(parents=True, exist_ok=True)

    # Create header if new file
    if not ICON_LOG_FILE.exists():
        with open(ICON_LOG_FILE, "w") as f:
            f.write("# Patched Icons Log\n")
            f.write("# This file tracks all icons that have been patched into Nerd Fonts Symbols\n")
            f.write("# Format: Icon Name | Unicode | Character | UTF-8 Hex | Date Added\n")
            f.write("=" * 80 + "\n\n")

    with open(ICON_LOG_FILE, "a") as f:
        f.write("\n" + "=" * 80 + "\n")
        f.write(f"Patch Date: {timestamp}\n")
        f.write(f"New Icons Added: {len(new_mappings)}\n")
        f.write("=" * 80 + "\n")
        f.write(f"{'ICON NAME':<25} {'UNICODE':<10} {'CHAR':<6} {'UTF-8 HEX':<12}\n")
        f.write("-" * 80 + "\n")
        for icon_name, codepoint in sorted(new_mappings):
            char = chr(codepoint)
            utf8_hex = char.encode("utf-8").hex()
            f.write(f"{icon_name:<25} U+{codepoint:04X}    {char:<6} {utf8_hex:<12}\n")
        f.write("=" * 80 + "\n")

    print_success(f"Saved {len(new_mappings)} new icon(s) to log: {ICON_LOG_FILE}")


def display_mappings(mappings: list[tuple[str, int]], new_mappings: list[tuple[str, int]], output_path: Path, installed: bool):
    """Display icon mappings after patching.

    NOTE: We don't display the actual glyph character here because:
    1. The terminal's font cache won't be updated yet (even after fc-cache)
    2. Displaying PUA characters before font update can crash some terminals
    Instead, users should use 'nerd -L' after the terminal restarts to see glyphs.
    """
    # Flush any pending output to ensure proper ordering
    sys.stdout.flush()
    sys.stderr.flush()

    if new_mappings:
        print("", file=sys.stderr)
        print_success("=" * 42)
        print_success("Newly Patched Symbols:")
        print_success("=" * 42)
        print(f"{GREEN}{'ICON NAME':<25} {'UNICODE':<10} {'UTF-8 HEX':<12} {'JS/GJS ESCAPE'}{NC}", file=sys.stderr)
        print_success("-" * 80)
        for icon_name, codepoint in sorted(new_mappings):
            char = chr(codepoint)
            utf8_hex = char.encode("utf-8").hex()
            js_escape = get_js_escape(codepoint)
            print(f"{GREEN}{icon_name:<25} U+{codepoint:04X}    {utf8_hex:<12} {js_escape}{NC}", file=sys.stderr)
        print_success("=" * 42)
        print("", file=sys.stderr)

        if installed:
            print_info(f"Patched font location: {FONT_DIR_USER}")
            for font_file in output_path.iterdir():
                if font_file.suffix.lower() in (".ttf", ".otf"):
                    print_info(f"  - {font_file.name}")
            print("", file=sys.stderr)

        print_info("Usage examples:")
        print_info("  - In GJS/AGS: use the JS/GJS Escape string")
        print_info("  - Use printf with UTF-8 hex: printf '\\xef\\x98\\xa9'")
        print_info("  - View glyphs after restarting terminal: nerd -l")
        print("", file=sys.stderr)
        print_info(f"New icons logged to: {ICON_LOG_FILE}")
        print_warning("NOTE: Restart your terminal to see updated glyphs")

    elif mappings:
        print("", file=sys.stderr)
        print_info("=" * 42)
        print_info("No new icons added (all icons already exist in font)")
        print_info("=" * 42)
        print(f"{'ICON NAME':<25} {'UNICODE':<10} {'UTF-8 HEX':<12} {'JS/GJS ESCAPE'}", file=sys.stderr)
        print_info("-" * 80)
        for icon_name, codepoint in sorted(mappings):
            char = chr(codepoint)
            utf8_hex = char.encode("utf-8").hex()
            js_escape = get_js_escape(codepoint)
            print(f"{icon_name:<25} U+{codepoint:04X}    {utf8_hex:<12} {js_escape}", file=sys.stderr)
        print_info("=" * 42)
        print("", file=sys.stderr)
        print_info("View all patched symbols: nerd -l")


def main():
    parser = argparse.ArgumentParser(
        description="Add icons from multiple providers to Nerd Fonts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -i vivaldi                    Search all providers (simple->lucide->material->bootstrap)
    %(prog)s -i vivaldi -p simple          Search only Simple Icons
    %(prog)s -i home -p lucide,bootstrap   Search Lucide first, then Bootstrap
    %(prog)s -i home -p lu                 Use alias 'lu' for Lucide
    %(prog)s -x viv                        Search remote providers for 'viv'
    %(prog)s -x viv -p material,simple     Search only specified providers
    %(prog)s -i ./icons/*                  Add all SVGs in directory (with confirmation)
    %(prog)s -i ./icons/* -y               Add all SVGs without confirmation
    %(prog)s -i ./icon.svg -n custom-name  Custom name for single icon
    %(prog)s -i ./chatgpt.svg              Patch with local SVG (auto-detected)
    %(prog)s -i ./new.svg -u myicon        Update existing 'myicon' with new SVG
    %(prog)s -i vivaldi -d -S F600         Duplicate icons at new codepoints (F600+)
    %(prog)s -l                            List all custom symbols
    %(prog)s -l -a                         List with all encoding formats
    %(prog)s -l -j                         List symbols in JSON format
    %(prog)s -s cloud                      Search local symbols by name
    %(prog)s -R myicon                     Remove 'myicon' from all font files
    %(prog)s --rename old-name new-name    Rename a symbol in all font files

Provider aliases:
    simple: simpleicons, simple-icons, si
    lucide: lu
    material: mdi, materialdesign, material-design
    bootstrap: bi, bootstrap-icons
        """,
    )

    # Mode selection
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-l", "--list", action="store_true", help="List all custom symbols in installed Nerd Fonts")
    mode.add_argument("-s", "--search", metavar="QUERY", help="Search local symbols by name (substring match)")
    mode.add_argument("-x", "--search-remote", metavar="QUERY", help="Search remote providers for icons matching QUERY")
    mode.add_argument("-t", "--test", metavar="FONT", help="Test mode - display all icons in font file")
    mode.add_argument("-R", "--remove", metavar="NAME", help="Remove a custom symbol by name from all font files")
    mode.add_argument("--rename", nargs=2, metavar=("OLD", "NEW"), help="Rename a custom symbol in all font files")

    # Output format options
    parser.add_argument("-a", "--all-formats", action="store_true", help="Show all encoding formats (Unicode, UTF-8 hex, JS/GJS escape)")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format (for -l/--list, -s/--search, -x/--search-remote)")

    # Patch mode options
    parser.add_argument("-i", "--icons", metavar="ICONS", help="Comma-separated icon names or local SVG paths (wildcards supported)")
    parser.add_argument("-p", "--providers", metavar="PROVIDERS", help="Comma-separated providers to search: simple, lucide, material, bootstrap")
    parser.add_argument("-n", "--name", metavar="NAME", help="Custom name for icon (single icon only, not with wildcards)")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompts (for wildcards)")
    parser.add_argument("-u", "--update", metavar="REF", help="Update existing symbol by name or codepoint (e.g., 'myicon' or 'ue069')")
    parser.add_argument("-d", "--duplicate", action="store_true", help="Add copies at new codepoints (keeps existing icons at old locations)")
    parser.add_argument("-f", "--fonts", metavar="PATTERNS", default="symbols", help="Comma-separated Nerd Font patterns (default: symbols)")
    parser.add_argument("-O", "--output", metavar="PATH", default="./patched-fonts", help="Output path for patched fonts")
    parser.add_argument("-o", "--options", metavar="OPTS", default="install", help="Options: install, cleanup (default: install)")
    parser.add_argument("-S", "--start", metavar="HEX", help="Starting Unicode codepoint in hex")

    args = parser.parse_args()

    # List mode
    if args.list:
        return list_symbols(show_all_formats=args.all_formats, output_json=args.json)

    # Search mode
    if args.search:
        return list_symbols(show_all_formats=args.all_formats, output_json=args.json, search_query=args.search)

    # Test mode
    if args.test:
        return test_font(args.test)

    # Remove mode
    if args.remove:
        return remove_symbol(args.remove)

    # Rename mode
    if args.rename:
        return rename_symbol(args.rename[0], args.rename[1])

    # Remote search mode
    if args.search_remote:
        # Parse providers if specified
        providers = None
        if args.providers:
            try:
                providers = parse_providers(args.providers)
            except ValueError as e:
                print_error(str(e))
                return 1
        return search_remote_icons(args.search_remote, providers, output_json=args.json)

    # Update mode - update a specific symbol by name or codepoint
    if args.update:
        # Require icon source for update
        if not args.icons:
            print_error("Update mode requires an icon source: -i (icon name or local SVG path)")
            return 1

        # Parse providers if specified
        providers = None
        if args.providers:
            try:
                providers = parse_providers(args.providers)
            except ValueError as e:
                print_error(str(e))
                return 1

        # For update, we only allow a single input
        inputs = [i.strip() for i in args.icons.split(",")]
        if len(inputs) > 1:
            print_error("Update mode only accepts a single icon")
            return 1

        icon_input = inputs[0]

        # Classify as local or remote
        try:
            _, is_local = classify_icon_input(icon_input, providers_specified=bool(providers))
        except (FileNotFoundError, ValueError) as e:
            print_error(str(e))
            return 1

        if is_local:
            svg_path = Path(icon_input)
            return update_symbol(args.update, svg_path)
        else:
            # Download the icon using multi-provider search
            temp_dir = Path(tempfile.mkdtemp())
            success, error = download_icon_from_providers(icon_input, temp_dir, providers)
            if not success:
                print_error(f"Failed to download icon '{icon_input}': {error}")
                shutil.rmtree(temp_dir)
                return 1
            svg_path = temp_dir / f"{icon_input}.svg"
            result = update_symbol(args.update, svg_path)
            shutil.rmtree(temp_dir)
            return result

    # Patch mode - require icon source
    if not args.icons:
        print_error("Icon source required: -i (icon names or local SVG paths)")
        parser.print_help()
        return 1

    # Parse providers if specified
    providers = None
    if args.providers:
        try:
            providers = parse_providers(args.providers)
        except ValueError as e:
            print_error(str(e))
            return 1

    # Parse inputs
    inputs = [i.strip() for i in args.icons.split(",")]
    inputs = [i for i in inputs if i]  # Remove empty strings

    # Check for wildcard patterns
    has_wildcard = any('*' in i or '?' in i for i in inputs)

    # Validate -n/--name usage
    if args.name:
        if has_wildcard:
            print_error("-n/--name cannot be used with wildcard patterns")
            return 1
        if len(inputs) > 1:
            print_error("-n/--name can only be used with a single icon")
            return 1

    # Wildcards must be sole input
    if has_wildcard and len(inputs) > 1:
        print_error("Wildcard patterns cannot be combined with other inputs")
        return 1

    # Handle wildcard expansion
    if has_wildcard:
        pattern = inputs[0]
        matched_files = expand_wildcard_paths(pattern)
        if not matched_files:
            print_error(f"No SVG files matched pattern: {pattern}")
            return 1

        if not confirm_wildcard_patch(matched_files, args.yes):
            print_info("Cancelled.")
            return 0

        # Replace inputs with matched files
        inputs = [str(f) for f in matched_files]

    print_info("Starting icon patcher")
    print_info("=" * 42)
    if providers:
        print_info(f"Using providers: {', '.join(providers)}")
    else:
        print_info(f"Using providers: {', '.join(DEFAULT_PROVIDER_ORDER)} (default order)")

    # Create temp directory for icons
    temp_dir = Path(tempfile.mkdtemp())
    icons_dir = temp_dir / "icons"
    icons_dir.mkdir()

    failed_icons = []

    # Parse options early so they're available in finally block
    options = [o.strip().lower() for o in args.options.split(",")]
    do_install = "install" in options
    do_cleanup = "cleanup" in options

    try:
        # Classify inputs as local or remote
        remote_icons = []
        local_svgs = []

        for icon_input in inputs:
            if not icon_input:
                continue
            try:
                name, is_local = classify_icon_input(icon_input, providers_specified=bool(providers))
                if is_local:
                    local_svgs.append(name)
                else:
                    remote_icons.append(name)
            except FileNotFoundError as e:
                print_error(str(e))
                failed_icons.append(f"{icon_input} (file not found)")
            except ValueError as e:
                print_error(str(e))
                failed_icons.append(f"{icon_input} (invalid)")

        # Download remote icons using multi-provider search
        if remote_icons:
            print_info("Downloading icons from remote providers...")
            for icon_name in remote_icons:
                # Apply custom name only for single icon
                custom_name = args.name if len(remote_icons) == 1 and len(local_svgs) == 0 else None
                success, error = download_icon_from_providers(icon_name, icons_dir, providers, custom_name)
                if not success:
                    print_error(f"  Failed: {icon_name} - {error}")
                    failed_icons.append(f"{icon_name} ({error})")

        # Copy local SVGs
        if local_svgs:
            # Apply custom name only for single local icon
            custom_name = args.name if len(local_svgs) == 1 and len(remote_icons) == 0 else None
            failed_icons.extend(copy_local_svgs(local_svgs, icons_dir, custom_name))

        # Check we have at least one icon
        icon_count = len(list(icons_dir.glob("*.svg")))
        if icon_count == 0:
            print_error("No icons were successfully processed. Cannot continue.")
            return 1

        if failed_icons:
            print_warning(f"Some icons failed to process, but continuing with {icon_count} successful icon(s)...")

        # Find fonts
        font_patterns = [p.strip() for p in args.fonts.split(",")]
        fonts = find_fonts(font_patterns)
        if not fonts:
            return 1

        # Parse start codepoint
        start_cp = None
        if args.start:
            try:
                start_cp = int(args.start, 16)
                print_info(f"Using user-specified starting codepoint U+{start_cp:04X}")
            except ValueError:
                print_error(f"Invalid hex codepoint: {args.start}")
                return 1

        # Patch fonts
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)

        print_info("Patching fonts with icons...")

        all_mappings = []
        all_new_mappings = []

        for font_file in fonts:
            # Output uses same filename (patched font replaces original)
            out_name = font_file.name
            print_info(f"  Patching {font_file.name}...")

            out_file = output_path / out_name

            try:
                mappings, new_mappings = patch_font(font_file, icons_dir, out_file, start_cp, False, args.duplicate)
                print_success(f"    Created: {out_name}")

                if not all_mappings:
                    all_mappings = mappings
                    all_new_mappings = new_mappings

            except Exception as e:
                print_error(f"    Failed to patch {font_file.name}: {e}")

        if do_install:
            install_fonts(output_path)

        # Save log and display results
        save_to_log(all_new_mappings)
        display_mappings(all_mappings, all_new_mappings, output_path, do_install)

        # Report failed icons
        if failed_icons:
            print("", file=sys.stderr)
            print_warning("=" * 42)
            print_warning(f"Failed Icons Summary ({len(failed_icons)} failed):")
            print_warning("=" * 42)
            for failed in failed_icons:
                print_error(f"  - {failed}")
            print_warning("=" * 42)

        print_success("=" * 42)
        print_success(f"All done! Patched fonts are in: {output_path}")

        if do_install:
            print_info("Fonts have been installed and are ready to use")
            print_info(f"  Install location: {FONT_DIR_USER}")
        else:
            print_info("To install fonts, run with -o install option")

    finally:
        if do_cleanup:
            print_info("Cleaning up temporary files...")
            shutil.rmtree(temp_dir)
            print_success("Cleanup complete")
        else:
            print_info(f"Temporary files kept in: {temp_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
