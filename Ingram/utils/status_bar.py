"""Enhanced console dashboard for WRAITH scanner"""
import io
import os
import random
import re
import shutil
import sys
import time

from . import timer
from .color import color


def _ensure_utf8_stdout():
    """Ensure stdout can handle Unicode on Windows"""
    if sys.platform == 'win32':
        try:
            # Enable UTF-8 mode for Windows console
            os.system('')  # enables VT100 escape sequences on Win10+
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            elif sys.stdout.encoding != 'utf-8':
                sys.stdout = io.TextIOWrapper(
                    sys.stdout.buffer, encoding='utf-8', errors='replace'
                )
        except Exception:
            pass


# Box-drawing characters (safe in UTF-8)
BOX_H = '\u2500'   # ─
BOX_V = '\u2502'   # │
BOX_TL = '\u250C'  # ┌
BOX_TR = '\u2510'  # ┐
BOX_BL = '\u2514'  # └
BOX_BR = '\u2518'  # ┘
BOX_LT = '\u251C'  # ├
BOX_RT = '\u2524'  # ┤

# Progress bar characters
BAR_FULL = '\u2588'   # █
BAR_EMPTY = '\u2591'  # ░

# Spinner animations
SPINNERS = [
    ['\u25D0', '\u25D3', '\u25D1', '\u25D2'],           # ◐◓◑◒
    ['\u2190', '\u2196', '\u2191', '\u2197', '\u2192', '\u2198', '\u2193', '\u2199'],  # arrows
    ['/', '-', '\\', '|'],                                # simple
    ['.  ', '.. ', '...', ' ..', '  .', '   '],          # dots
    ['[=   ]', '[ =  ]', '[  = ]', '[   =]', '[  = ]', '[ =  ]'],  # bouncer
]


def _get_terminal_width():
    """Get terminal width, fallback to 80"""
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def _progress_bar(percent, width=30):
    """Build a colored progress bar string"""
    filled = int(width * percent)
    bar = BAR_FULL * filled + BAR_EMPTY * (width - filled)

    # Color gradient: red -> yellow -> green based on progress
    if percent < 0.33:
        return color.red(bar, 'bright')
    elif percent < 0.66:
        return color.yellow(bar, 'bright')
    else:
        return color.green(bar, 'bright')


def _calc_scan_rate(data):
    """Calculate targets/sec from recent samples"""
    with data.rate_samples_lock:
        samples = list(data.rate_samples)
    if len(samples) < 2:
        return 0.0
    oldest_time, oldest_done = samples[0]
    newest_time, newest_done = samples[-1]
    dt = newest_time - oldest_time
    if dt <= 0:
        return 0.0
    return (newest_done - oldest_done) / dt


def _format_rate(rate):
    """Format scan rate nicely"""
    if rate >= 100:
        return f"{int(rate)}/s"
    elif rate >= 10:
        return f"{rate:.1f}/s"
    elif rate > 0:
        return f"{rate:.2f}/s"
    else:
        return "-.--/s"


def _visible_len(text):
    """Get visible length of text, stripping ANSI escape codes and OSC 8 hyperlinks"""
    # Strip OSC 8 hyperlink sequences: \033]8;;...\033\\
    text = re.sub(r'\033\]8;;[^\033]*\033\\', '', text)
    # Strip standard ANSI color/style codes
    return len(re.sub(r'\x1b\[[0-9;]*m', '', text))


def _pad_line(text, width):
    """Pad a line to fill the box width, accounting for ANSI escape codes"""
    padding = max(0, width - _visible_len(text))
    return text + ' ' * padding


def _safe_write(text):
    """Write text to stdout, handling encoding errors gracefully"""
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except UnicodeEncodeError:
        # Fallback: strip problematic characters
        safe = text.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(
            sys.stdout.encoding or 'utf-8', errors='replace'
        )
        sys.stdout.write(safe)
        sys.stdout.flush()


def _hyperlink(url, display_text):
    """Create a clickable OSC 8 terminal hyperlink.
    Supported by Windows Terminal, iTerm2, VS Code terminal, etc.
    Falls back to plain text in unsupported terminals."""
    return f"\033]8;;{url}\033\\{display_text}\033]8;;\033\\"


def _dashboard():
    """Create the enhanced dashboard renderer"""
    spinner_set = random.choice(SPINNERS)
    spin_idx = [0]
    last_rate = [0.0]
    prev_num_lines = [0]

    def render(core):
        data = core.data
        total = data.total
        done = data.done
        found = data.found
        snapshots = core.snapshot_pipeline.get_done()
        elapsed = timer.get_time_stamp() - data.create_time + data.runned_time

        # Calculations
        percent = done / max(total, 1)
        rate = _calc_scan_rate(data)
        if rate > 0:
            last_rate[0] = rate
        display_rate = last_rate[0]

        # ETA
        remaining = total - done
        if display_rate > 0:
            eta_secs = remaining / display_rate
        else:
            eta_secs = elapsed * (total / max(done, 1)) - elapsed
        eta_str = timer.time_formatter(max(0, eta_secs))
        elapsed_str = timer.time_formatter(elapsed)

        # Spinner
        spin = spinner_set[spin_idx[0] % len(spinner_set)]
        spin_idx[0] += 1

        # Terminal width
        tw = _get_terminal_width()

        # Build lines
        lines = []

        # Top border
        lines.append(color.cyan(f"{BOX_TL}{BOX_H * (tw - 2)}{BOX_TR}", 'dim'))

        # Header: WRAITH SCANNER + status + resume indicator
        status_text = "SCANNING" if done < total else "COMPLETE"
        if done < total:
            status_colored = color.yellow(f"[{status_text}]", 'bright')
        else:
            status_colored = color.green(f"[{status_text}]", 'bright')
        resume_tag = f"  {color.magenta('[RESUMED]', 'bright')}" if data.is_resumed else ""
        header_line = f"  {color.green(spin, 'bright')} WRAITH SCANNER  {status_colored}{resume_tag}"
        lines.append(color.cyan(BOX_V, 'dim') + _pad_line(header_line, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Separator
        lines.append(color.cyan(f"{BOX_LT}{BOX_H * (tw - 2)}{BOX_RT}", 'dim'))

        # Progress bar row
        bar_width = min(tw - 24, 40)
        if bar_width < 10:
            bar_width = 10
        pbar = _progress_bar(percent, bar_width)
        pct_str = color.white(f"{percent * 100:5.1f}%", 'bright')
        prog_line = f"  Progress {pbar} {pct_str}"
        lines.append(color.cyan(BOX_V, 'dim') + _pad_line(prog_line, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Stats row 1: Targets + Rate
        done_str = color.blue(str(done), 'bright')
        total_str = color.blue(str(total), 'bright')
        rate_str = color.magenta(_format_rate(display_rate), 'bright')
        stats1 = f"  Targets: {done_str}/{total_str}    Rate: {rate_str}"
        lines.append(color.cyan(BOX_V, 'dim') + _pad_line(stats1, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Stats row 2: Time + ETA
        elapsed_colored = color.cyan(elapsed_str, 'bright')
        eta_colored = color.white(eta_str, 'bright')
        stats2 = f"  Elapsed: {elapsed_colored}    ETA: {eta_colored}"
        lines.append(color.cyan(BOX_V, 'dim') + _pad_line(stats2, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Stats row 3: Found + Snapshots
        found_str = color.red(str(found), 'bright') if found else color.white('0', 'dim')
        snap_str = color.yellow(str(snapshots), 'bright') if snapshots else color.white('0', 'dim')
        stats3 = f"  Vulns Found: {found_str}    Snapshots: {snap_str}"
        lines.append(color.cyan(BOX_V, 'dim') + _pad_line(stats3, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Current target + per-target timing
        with data.current_target_lock:
            current_ip = data.current_target
        with data.target_time_lock:
            target_start = data.target_start_time
            last_target_t = data.last_target_time
            total_target_t = data.total_target_time

        if current_ip:
            # Time spent on current IP
            if target_start > 0:
                current_t = time.time() - target_start
                cur_str = color.white(f"{current_t:.1f}s", 'bright')
            else:
                cur_str = color.white("-.--s", 'dim')

            # Average time per IP
            completed = max(done, 1)
            if total_target_t > 0 and done > 0:
                avg_t = total_target_t / done
                avg_str = color.cyan(f"{avg_t:.1f}s", 'bright')
            else:
                avg_str = color.white("-.--s", 'dim')

            # Last IP time
            if last_target_t > 0:
                last_str = color.yellow(f"{last_target_t:.1f}s", 'bright')
            else:
                last_str = color.white("-.--s", 'dim')

            target_line = f"  Scanning: {color.white(current_ip, 'bright')}  Current: {cur_str}  Avg: {avg_str}  Last: {last_str}"
            lines.append(color.cyan(BOX_V, 'dim') + _pad_line(target_line, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Last vulnerable target (clickable link)
        with data.last_vuln_url_lock:
            last_url = data.last_vuln_url
        if last_url:
            clickable = _hyperlink(last_url, last_url)
            link_line = f"  Last Hit: {color.red(clickable, 'bright')}  (click to open)"
            lines.append(color.cyan(BOX_V, 'dim') + _pad_line(link_line, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Recent findings section (only if any found)
        with data.recent_vulns_lock:
            recent = list(data.recent_vulns)

        if recent:
            lines.append(color.cyan(f"{BOX_LT}{BOX_H * (tw - 2)}{BOX_RT}", 'dim'))
            findings_header = f"  {color.red('RECENT FINDINGS', 'bright')}"
            lines.append(color.cyan(BOX_V, 'dim') + _pad_line(findings_header, tw - 2) + color.cyan(BOX_V, 'dim'))

            for vuln in recent[-3:]:  # show last 3
                if len(vuln) >= 6:
                    ip, port, product = vuln[0], vuln[1], vuln[2]
                    user, pwd, poc_name = vuln[3], vuln[4], vuln[5]
                    pwd_display = pwd if pwd else '(blank)'
                    scheme = 'https' if str(port) in ('443', '8443') else 'http'
                    url = f"{scheme}://{ip}:{port}"
                    ip_link = _hyperlink(url, f"{ip}:{port}")
                    entry = f"    {color.red('>', 'bright')} {color.white(ip_link, 'bright')} [{color.yellow(product)}] {user}:{pwd_display} ({color.cyan(poc_name)})"
                elif len(vuln) >= 3:
                    scheme = 'https' if str(vuln[1]) in ('443', '8443') else 'http'
                    url = f"{scheme}://{vuln[0]}:{vuln[1]}"
                    ip_link = _hyperlink(url, f"{vuln[0]}:{vuln[1]}")
                    entry = f"    {color.red('>', 'bright')} {color.white(ip_link, 'bright')} [{color.yellow(vuln[2])}]"
                else:
                    entry = f"    {color.red('>', 'bright')} {','.join(str(v) for v in vuln)}"
                lines.append(color.cyan(BOX_V, 'dim') + _pad_line(entry, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Device breakdown (only if vulnerabilities found)
        with data.device_counts_lock:
            dev_counts = dict(data.device_counts)

        if dev_counts:
            lines.append(color.cyan(f"{BOX_LT}{BOX_H * (tw - 2)}{BOX_RT}", 'dim'))
            dev_header = f"  {color.magenta('DEVICE BREAKDOWN', 'bright')}"
            lines.append(color.cyan(BOX_V, 'dim') + _pad_line(dev_header, tw - 2) + color.cyan(BOX_V, 'dim'))

            max_count = max(dev_counts.values()) if dev_counts else 1
            mini_bar_width = min(15, tw - 30)
            if mini_bar_width < 3:
                mini_bar_width = 3
            for dev, count in sorted(dev_counts.items(), key=lambda x: -x[1]):
                bar_len = max(1, int(count / max(max_count, 1) * mini_bar_width))
                mini_bar = color.green(BAR_FULL * bar_len, 'bright')
                dev_line = f"    {color.yellow(f'{dev:>12}')} {mini_bar} {color.white(str(count), 'bright')}"
                lines.append(color.cyan(BOX_V, 'dim') + _pad_line(dev_line, tw - 2) + color.cyan(BOX_V, 'dim'))

        # Bottom border
        lines.append(color.cyan(f"{BOX_BL}{BOX_H * (tw - 2)}{BOX_BR}", 'dim'))

        # Handle dynamic line growth: if dashboard grew, print extra newlines first
        num_lines = len(lines)
        if num_lines > prev_num_lines[0] and prev_num_lines[0] > 0:
            extra = num_lines - prev_num_lines[0]
            _safe_write('\n' * extra)

        # Move cursor up and redraw
        if prev_num_lines[0] > 0:
            move_up = max(num_lines, prev_num_lines[0])
            _safe_write(f"\033[{move_up}A")

        output = '\n'.join(lines)
        _safe_write(output + '\n')

        prev_num_lines[0] = num_lines

    return render


def status_bar(core):
    """Render the enhanced scanning dashboard"""
    _ensure_utf8_stdout()

    render = _dashboard()

    try:
        while not core.finish():
            try:
                render(core)
            except Exception:
                pass
            time.sleep(0.2)

        # Final draw
        render(core)
    except Exception:
        pass
