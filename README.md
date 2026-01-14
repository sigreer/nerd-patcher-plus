# Nerd Patcher Plus

Add icons from multiple providers to Nerd Fonts. Supports Simple Icons, Lucide, Material Design Icons, and Bootstrap Icons.

## Features

- **Multi-provider support**: Search and download icons from Simple Icons, Lucide, Material Design Icons, and Bootstrap Icons
- **Configurable search order**: Specify which providers to search and in what order
- **Remote search**: Search for icons across all providers before downloading
- **Wildcard expansion**: Batch add local SVG files with glob patterns
- **Custom naming**: Override icon names when adding single icons
- **Symbol management**: List, search, update, remove, and rename patched symbols

## Requirements

- Python 3.10+
- FontForge with Python bindings (`sudo pacman -S fontforge` on Arch Linux)
- Nerd Fonts Symbols Only font installed

## Installation

```bash
# Clone the repository
git clone https://github.com/sigreer/nerd-patcher-plus.git
cd nerd-patcher-plus

# Make the script executable
chmod +x nerd-symbol-patcher.py

# Optional: Create a symlink for easy access
ln -s "$(pwd)/nerd-symbol-patcher.py" ~/.local/bin/nerd
```

## Usage

### Adding Icons

```bash
# Search all providers (simple -> lucide -> material -> bootstrap)
nerd -i vivaldi

# Search specific provider(s)
nerd -i home -p material
nerd -i home -p lucide,bootstrap

# Use provider aliases
nerd -i account -p mdi          # mdi = Material Design Icons
nerd -i heart -p bi             # bi = Bootstrap Icons
nerd -i github -p si            # si = Simple Icons
nerd -i arrow-right -p lu       # lu = Lucide

# Add local SVG files
nerd -i ./my-icon.svg
nerd -i ./icons/*.svg           # Wildcard (with confirmation)
nerd -i ./icons/*.svg -y        # Skip confirmation

# Custom naming
nerd -i ./icon.svg -n my-custom-name
nerd -i vivaldi -n vivaldi-browser
```

### Searching Remote Providers

```bash
# Search all providers
nerd -x github

# Search specific providers
nerd -x home -p material
nerd -x star -p mdi,lucide

# JSON output
nerd -x github -j
```

### Managing Symbols

```bash
# List all patched symbols
nerd -l
nerd -l -a                      # Show all encoding formats
nerd -l -j                      # JSON output

# Search local symbols
nerd -s cloud

# Update existing symbol
nerd -i ./new-icon.svg -u old-icon-name

# Remove symbol
nerd -R icon-name

# Rename symbol
nerd --rename old-name new-name
```

### Provider Aliases

| Provider | Aliases |
|----------|---------|
| `simple` | `simpleicons`, `simple-icons`, `si` |
| `lucide` | `lu` |
| `material` | `mdi`, `materialdesign`, `material-design` |
| `bootstrap` | `bi`, `bootstrap-icons` |

## Options

| Option | Description |
|--------|-------------|
| `-i, --icons ICONS` | Comma-separated icon names or local SVG paths (wildcards supported) |
| `-p, --providers PROVIDERS` | Comma-separated providers to search |
| `-n, --name NAME` | Custom name for icon (single icon only) |
| `-y, --yes` | Skip confirmation prompts |
| `-x, --search-remote QUERY` | Search remote providers for icons |
| `-l, --list` | List all patched symbols |
| `-s, --search QUERY` | Search local symbols by name |
| `-u, --update REF` | Update existing symbol by name or codepoint |
| `-R, --remove NAME` | Remove a symbol |
| `--rename OLD NEW` | Rename a symbol |
| `-a, --all-formats` | Show all encoding formats |
| `-j, --json` | Output in JSON format |
| `-d, --duplicate` | Add copies at new codepoints |
| `-f, --fonts PATTERNS` | Font patterns to patch (default: symbols) |
| `-O, --output PATH` | Output path for patched fonts |
| `-S, --start HEX` | Starting Unicode codepoint |

## How It Works

1. Icons are downloaded from provider repositories (or copied from local paths)
2. SVGs are imported into the Nerd Fonts Symbols font using FontForge
3. Each icon is assigned a codepoint in the Private Use Area (starting at U+F600)
4. Icons are named with `sgc_` prefix (e.g., `sgc_github`)
5. The patched font is installed to `~/.local/share/fonts/NerdFontsSymbolsOnly/`

## Using Patched Icons

After patching, restart your terminal to see the new glyphs. Use the escape codes shown in the output:

```bash
# View patched symbols with escape codes
nerd -l

# Example output:
# github                    \uf620
# home                      \uf621
```

In your code/configs, use the Unicode escape:
- **Shell**: `echo -e "\uf620"`
- **JavaScript/GJS**: `"\uf620"`
- **Python**: `"\uf620"`

## License

MIT License
