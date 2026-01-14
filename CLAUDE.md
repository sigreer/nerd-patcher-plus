# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nerd Patcher Plus is a Python CLI tool that patches custom icons into Nerd Fonts. It downloads SVG icons from multiple providers (Simple Icons, Lucide, Material Design, Bootstrap) or accepts local SVGs, then embeds them into the Nerd Fonts Symbols font using FontForge.

## Running the Tool

```bash
# Run directly
python3 nerd-symbol-patcher.py -i <icon-name>

# Or via symlink (if installed)
nerd -i <icon-name>

# Check dependencies
python3 nerd-symbol-patcher.py --check-deps

# Verbose output (shows all processing details)
python3 nerd-symbol-patcher.py -i <icon-name> -v
```

## Architecture

This is a single-file Python script (`nerd-symbol-patcher.py`) with no external dependencies beyond FontForge.

### Key Components

- **Provider system**: Downloads icons from GitHub-hosted icon repositories (Simple Icons, Lucide, Material Design, Bootstrap). Provider aliases are defined in `PROVIDERS` dict.
- **Font patching**: Uses FontForge Python bindings to create glyphs in the Private Use Area (starting at U+F600). Glyphs are named with `sgc_` prefix.
- **Symbol management**: Supports listing (`-l`), searching (`-s`), updating (`-u`), removing (`-R`), and renaming (`--rename`) patched symbols.

### Important Implementation Details

- **Codepoint safety**: The code avoids codepoints where the low byte is 0x00-0x1F (ASCII control chars) as some terminals interpret these incorrectly. See `is_safe_codepoint()`.
- **FontForge output suppression**: `suppress_fontforge_output()` context manager redirects stdout/stderr during font operations to prevent terminal crashes from PUA character output.
- **Ghostty detection**: `is_safe_to_render_glyphs()` checks if running in Ghostty terminal and whether it was started after font updates, to avoid rendering issues.

### File Locations

- Patched fonts: `~/.local/share/fonts/NerdFontsSymbolsOnly/`
- Icon log: `~/.local/share/fonts/NerdFontsSymbolsOnly/patched-icons-log.txt`

## Dependencies

- Python 3.10+
- FontForge with Python bindings (`fontforge` and `psMat` modules)
- Nerd Fonts Symbols Only font must be installed
