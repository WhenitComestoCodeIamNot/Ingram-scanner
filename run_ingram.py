#! /usr/bin/env python3
# coding  : utf-8
# @Author : Jor<jorhelp@qq.com>
# @Date   : Wed Apr 20 00:17:30 HKT 2022
# @Desc   : WRAITH - Network camera vulnerability scanning tool

#=================== Must be at the very top ====================
import warnings; warnings.filterwarnings("ignore")
from gevent import monkey; monkey.patch_all(thread=False)
#================================================================

import hashlib
import os
import sys
from multiprocessing import Process

from loguru import logger

from Ingram import get_config
from Ingram import Core
from Ingram.utils import color
from Ingram.utils import common
from Ingram.utils import get_parse
from Ingram.utils import log
from Ingram.utils import logo
from Ingram.utils.timer import time_formatter


def _check_previous_state(config):
    """Check for a previous scan state and prompt the user to resume or start fresh.
    Returns True if user wants to start fresh (clear state), False to resume."""
    taskid = hashlib.md5((config.in_file + config.out_dir).encode('utf-8')).hexdigest()
    state_file = os.path.join(config.out_dir, f".{taskid}")

    if not os.path.exists(state_file):
        return False  # no previous state, nothing to clear

    try:
        with open(state_file, 'r') as f:
            line = f.readline().strip()
            if not line:
                return False
            _done, _found, _runned_time = line.split(',')
            prev_done = int(_done)
            prev_found = int(_found)
            prev_time = float(_runned_time)
    except Exception:
        return False

    if prev_done <= 0:
        return False

    # Show previous scan state
    print(color.cyan('=' * 60))
    print(color.yellow('  PREVIOUS SCAN DETECTED', 'bright'))
    print(color.cyan('=' * 60))
    print(f"  {color.green('Targets scanned:')}  {color.white(str(prev_done), 'bright')}")
    print(f"  {color.green('Vulns found:')}      {color.red(str(prev_found), 'bright')}")
    print(f"  {color.green('Time elapsed:')}     {color.white(time_formatter(prev_time), 'bright')}")
    print(f"  {color.green('Output dir:')}       {color.white(config.out_dir, 'bright')}")
    print(color.cyan('=' * 60))

    while True:
        print(f"  {color.yellow('[R]', 'bright')} Resume (from target {color.white(str(prev_done), 'bright')})  {color.yellow('[F]', 'bright')} Start fresh")
        try:
            choice = input(f"  {color.green('>', 'bright')} Choose [R/F]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit()

        if choice in ('R', ''):
            print(f"  {color.green('Resuming', 'bright')} from target {color.white(str(prev_done), 'bright')}...")
            return False  # don't clear, resume
        elif choice == 'F':
            # Clear state
            os.remove(state_file)
            vuln_file = os.path.join(config.out_dir, config.vulnerable)
            not_vuln_file = os.path.join(config.out_dir, config.not_vulnerable)
            for f in [vuln_file, not_vuln_file]:
                if os.path.exists(f):
                    open(f, 'w').close()
            print(f"  {color.yellow('Cleared.', 'bright')} Starting fresh...")
            return True  # cleared
        else:
            print(f"  {color.red('Invalid choice. Enter R or F.')}")


def run():
    try:
        # Ensure UTF-8 for block-character logo art on Windows
        from Ingram.utils.status_bar import _ensure_utf8_stdout
        _ensure_utf8_stdout()

        # Logo
        for icon, font in zip(*logo):
            print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")

        # Config
        args = get_parse()
        config = get_config(args)

        if not os.path.isdir(config.out_dir):
            os.mkdir(config.out_dir)
            os.mkdir(os.path.join(config.out_dir, config.snapshots))

        # Generate targets from Shodan/Censys if API keys provided
        if (getattr(config, 'shodan_key', None) and getattr(config, 'shodan_query', None)) or \
           (getattr(config, 'censys_id', None) and getattr(config, 'censys_query', None)):
            from Ingram.utils.target_sources import generate_targets_from_api
            api_targets_file = os.path.join(config.out_dir, 'api_targets.txt')
            if generate_targets_from_api(config, api_targets_file):
                # Append API targets to the input file
                print(f"{color.green('API targets saved to')} {color.yellow(api_targets_file)}")
                # If no input file provided or it doesn't exist, use API targets as input
                if not os.path.isfile(config.in_file):
                    # Override in_file in config (need to recreate since namedtuple is immutable)
                    config = config._replace(in_file=api_targets_file)
                else:
                    # Append API targets to existing input file
                    with open(config.in_file, 'a') as dst, open(api_targets_file, 'r') as src:
                        dst.write('\n')
                        dst.write(src.read())

        if not os.path.isfile(config.in_file):
            print(f"{color.red('the input file')} {color.yellow(config.in_file)} {color.red('does not exist!')}")
            sys.exit()

        # Log configuration
        log.config_logger(os.path.join(config.out_dir, config.log), config.debug)

        # Check for previous scan state and prompt user
        _check_previous_state(config)

        # Print scan config summary
        print(f"{color.green('Scan speed:')} {color.yellow(config.scan_speed)}"
              f"  {color.green('Threads:')} {color.yellow(str(config.th_num))}"
              f"  {color.green('Randomize:')} {color.yellow(str(config.randomize))}")
        if config.proxy_rotator.enabled:
            print(f"{color.green('Proxies:')} {color.yellow(str(len(config.proxy_rotator.proxies)))}")

        # Launch scan
        core = Core(config)
        if common.os_check() == 'windows':
            # Windows: run in-process (multiprocessing.Process.start() has
            # permission issues with gevent's monkey-patched handles).
            # Ctrl+C is handled inside Core.run() via shutdown_event.
            core.run()
        else:
            p = Process(target=core.run)
            p.start()
            # Polling join so KeyboardInterrupt is delivered promptly
            while p.is_alive():
                p.join(timeout=0.5)

    except KeyboardInterrupt:
        print()
        print(f"{color.yellow('Ctrl+C pressed — shutting down...', 'bright')}")
        logger.warning('Ctrl+C was pressed')
        try:
            p.terminate()
            p.join(timeout=3)
            if p.is_alive():
                p.kill()
        except Exception:
            pass
        sys.exit(130)

    except Exception as e:
        logger.error(e)
        print(f"{color.red('error occurred, see the')} {color.yellow('log.txt')} "
              f"{color.red('for more information.')}")
        sys.exit(1)


if __name__ == '__main__':
    run()
