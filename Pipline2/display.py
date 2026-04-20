"""
display.py — Hacker-themed terminal output formatting engine.
Provides ANSI-colored output with bold text, tables, section headers, and status indicators.
"""

import os
import datetime
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows ANSI support
init(autoreset=True)

# ==================== COLOR SHORTCUTS ====================
G = Fore.GREEN          # Hacker green
R = Fore.RED            # Error / malicious
C = Fore.CYAN           # Info / headers
Y = Fore.YELLOW         # Warning
M = Fore.MAGENTA        # Highlights
W = Fore.WHITE          # Normal text
DG = Fore.LIGHTGREEN_EX # Light green
LR = Fore.LIGHTRED_EX   # Bright red
LC = Fore.LIGHTCYAN_EX  # Bright cyan
B = Style.BRIGHT        # Bold
D = Style.DIM           # Dim
RST = Style.RESET_ALL   # Reset


# ==================== BANNER ====================
def print_banner():
    """Print the hacker-themed startup banner."""
    banner = f"""
{G}{B}
     ██████╗ █████╗ ████████╗███████╗███╗   ██╗██╗███████╗███████╗
    ██╔════╝██╔══██╗╚══██╔══╝██╔════╝████╗  ██║██║██╔════╝██╔════╝
    ██║     ███████║   ██║   ███████╗██╔██╗ ██║██║█████╗  █████╗  
    ██║     ██╔══██║   ██║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  
    ╚██████╗██║  ██║   ██║   ███████║██║ ╚████║██║██║     ██║     
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     
{RST}
{C}{B}    ╔══════════════════════════════════════════════════════════════╗
    ║{W}  🐱  CatSniff — Threat Intelligence Scanner  v2.0          {C}║
    ║{DG}  ▸ VirusTotal  ▸ IPInfo  ▸ AbuseIPDB                     {C}║
    ║{D}{W}  ▸ Domain Recon ▸ SSL Cert ▸ WHOIS ▸ Subdomains           {C}║
    ╚══════════════════════════════════════════════════════════════╝{RST}
{D}{G}    [{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CatSniff initialized...{RST}
"""
    print(banner)


# ==================== SECTION HEADERS ====================
def print_section_header(title: str, icon: str = "📊"):
    """Print a styled section header."""
    width = 62
    print(f"\n{C}{B}{'═' * width}{RST}")
    print(f"{C}{B}  {icon}  {title.upper()}{RST}")
    print(f"{C}{B}{'═' * width}{RST}")


def print_sub_header(title: str):
    """Print a smaller sub-section header."""
    print(f"\n  {DG}{B}┌─── {title} ───{RST}")


def print_divider(char="─", width=62):
    """Print a thin divider line."""
    print(f"  {D}{G}{char * width}{RST}")


# ==================== KEY-VALUE DISPLAY ====================
def print_kv(key: str, value, indent: int = 4):
    """Print a bold key with a colored value."""
    prefix = " " * indent
    if value is None or value == '' or value == 'N/A':
        val_str = f"{D}N/A{RST}"
    else:
        val_str = f"{W}{B}{value}{RST}"
    print(f"{prefix}{G}▸ {C}{key}:{RST} {val_str}")


def print_kv_highlight(key: str, value, indent: int = 4):
    """Print a key-value pair with the value highlighted in yellow/magenta."""
    prefix = " " * indent
    if value is None:
        val_str = f"{D}N/A{RST}"
    else:
        val_str = f"{Y}{B}{value}{RST}"
    print(f"{prefix}{G}▸ {C}{key}:{RST} {val_str}")


# ==================== TABLE DISPLAY ====================
def print_table(headers: list, rows: list, indent: int = 4):
    """Print a formatted table with box-drawing characters."""
    if not rows:
        print_warning("No data to display", indent)
        return

    # Calculate column widths
    str_rows = [[str(cell) if cell is not None else "N/A" for cell in row] for row in rows]
    col_widths = [max(len(h), *(len(row[i]) for row in str_rows)) for i, h in enumerate(headers)]
    # Cap widths to avoid super-wide columns
    col_widths = [min(w, 50) for w in col_widths]

    prefix = " " * indent

    # Top border
    top = f"{prefix}{G}┌" + "┬".join("─" * (w + 2) for w in col_widths) + f"┐{RST}"
    mid = f"{prefix}{G}├" + "┼".join("─" * (w + 2) for w in col_widths) + f"┤{RST}"
    bot = f"{prefix}{G}└" + "┴".join("─" * (w + 2) for w in col_widths) + f"┘{RST}"

    # Header row
    header_str = f"{prefix}{G}│"
    for i, h in enumerate(headers):
        header_str += f" {C}{B}{h:<{col_widths[i]}}{RST} {G}│"

    print(top)
    print(header_str)
    print(mid)

    # Data rows
    for row in str_rows:
        row_str = f"{prefix}{G}│"
        for i, cell in enumerate(row):
            truncated = cell[:col_widths[i]] if len(cell) > col_widths[i] else cell
            row_str += f" {W}{truncated:<{col_widths[i]}}{RST} {G}│"
        print(row_str)

    print(bot)


# ==================== ANALYSIS STATS BAR ====================
def print_analysis_stats(stats: dict, indent: int = 4):
    """Print VirusTotal analysis stats as a colored inline summary."""
    if not stats:
        print_warning("No analysis stats available", indent)
        return

    prefix = " " * indent
    mal = stats.get('malicious', 0)
    sus = stats.get('suspicious', 0)
    harm = stats.get('harmless', 0)
    undet = stats.get('undetected', 0)
    total = mal + sus + harm + undet

    # Threat level color
    if mal > 5:
        threat_color = LR
        threat_label = "⚠️  HIGH THREAT"
    elif mal > 0 or sus > 0:
        threat_color = Y
        threat_label = "⚡ SUSPICIOUS"
    else:
        threat_color = DG
        threat_label = "✅ CLEAN"

    print(f"{prefix}{threat_color}{B}{threat_label}{RST}")
    print(f"{prefix}{R}{B}  Malicious : {mal:>3}{RST}  "
          f"{Y}{B}Suspicious : {sus:>3}{RST}  "
          f"{G}{B}Harmless : {harm:>3}{RST}  "
          f"{D}Undetected : {undet:>3}{RST}  "
          f"{D}(Total: {total}){RST}")

    # Visual bar
    if total > 0:
        bar_width = 40
        mal_w = int((mal / total) * bar_width)
        sus_w = int((sus / total) * bar_width)
        harm_w = int((harm / total) * bar_width)
        undet_w = bar_width - mal_w - sus_w - harm_w

        bar = (f"{Back.RED}{'█' * mal_w}{RST}"
               f"{Back.YELLOW}{Fore.BLACK}{'█' * sus_w}{RST}"
               f"{Back.GREEN}{'█' * harm_w}{RST}"
               f"{Back.WHITE}{Fore.BLACK}{'░' * undet_w}{RST}")
        print(f"{prefix}  [{bar}]")


# ==================== STATUS MESSAGES ====================
def print_success(message: str, indent: int = 4):
    prefix = " " * indent
    print(f"{prefix}{G}{B}✅ {message}{RST}")


def print_error(message: str, indent: int = 4):
    prefix = " " * indent
    print(f"{prefix}{R}{B}❌ {message}{RST}")


def print_warning(message: str, indent: int = 4):
    prefix = " " * indent
    print(f"{prefix}{Y}{B}⚠️  {message}{RST}")


def print_info(message: str, indent: int = 4):
    prefix = " " * indent
    print(f"{prefix}{C}ℹ️  {message}{RST}")


def print_scanning(target: str, scan_type: str = ""):
    """Print a scanning-in-progress message."""
    type_str = f" ({scan_type})" if scan_type else ""
    print(f"\n{G}{B}  ⟩⟩⟩ Scanning{type_str}: {DG}{target}{RST}")
    print(f"  {D}{G}{'.' * 62}{RST}")


# ==================== API STATUS ====================
def print_api_status(api_results: dict):
    """Print API connectivity status in a compact table."""
    print_sub_header("API Connectivity")
    for api_name, status in api_results.items():
        if '✅' in status:
            color = G
        elif '❌' in status:
            color = R
        else:
            color = Y
        print(f"    {color}{B}{status}{RST}  {W}{api_name}{RST}")
    print()


# ==================== COMPLETION ====================
def print_complete(message: str = "Analysis Complete"):
    """Print a completion banner."""
    width = 62
    print(f"\n{G}{B}{'═' * width}")
    print(f"  ✨  {message.upper()}")
    print(f"{'═' * width}{RST}\n")


def print_ip_cascade_header(ip: str, source: str = ""):
    """Print header when cascading IP analysis from domain results."""
    src = f" (from {source})" if source else ""
    print(f"\n{M}{B}  ⟩⟩⟩ Cascading IP Analysis{src}: {Y}{ip}{RST}")
    print(f"  {D}{M}{'─' * 62}{RST}")


# ==================== ML THREAT GAUGE ====================
def print_threat_score(result: dict):
    """Print the final ML-calculated threat score with a visual gauge."""
    score = result.get('score', 0)
    level = result.get('level', 'UNKNOWN')
    color_name = result.get('color', 'WHITE')
    method = result.get('method', 'Unknown')
    
    # Map color name to colorama
    color_map = {
        'RED': LR,
        'YELLOW': Y,
        'CYAN': LC,
        'GREEN': DG,
        'WHITE': W
    }
    clr = color_map.get(color_name, W)
    
    width = 62
    print(f"\n{clr}{B}╔{'═' * (width-2)}╗{RST}")
    print(f"{clr}{B}║{RST}  {W}{B}ML RISK ASSESSMENT VERDICT{RST}{' ' * (width - 31)}{clr}{B}║{RST}")
    
    # Gauge
    bar_width = 40
    filled = int((score / 100) * bar_width)
    empty = bar_width - filled
    
    # Gradient bar look
    bar = f"{clr}{'█' * filled}{D}{W}{'░' * empty}{RST}"
    
    print(f"{clr}{B}║{RST}  {W}Score: {clr}{B}{score:<5}/ 100{RST}  [{bar}]  {clr}{B}║{RST}")
    print(f"{clr}{B}║{RST}  {W}Level: {clr}{B}{level:<47}{RST} {clr}{B}║{RST}")
    print(f"{clr}{B}║{RST}  {D}Method: {method:<46}{RST} {clr}{B}║{RST}")
    print(f"{clr}{B}╚{'═' * (width-2)}╝{RST}\n")
