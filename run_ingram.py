#! /usr/bin/env python3
# coding  : utf-8
# @Author : Jor<jorhelp@qq.com>
# @Date   : Wed Apr 20 00:17:30 HKT 2022
# @Desc   : Network camera vulnerability scanning tool

#=================== Must be at the very top ====================
import warnings; warnings.filterwarnings("ignore")
from gevent import monkey; monkey.patch_all(thread=False)
#================================================================

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


def run():
    try:
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

        # Print scan config summary
        print(f"\n{color.green('Scan speed:')} {color.yellow(config.scan_speed)}"
              f"  {color.green('Threads:')} {color.yellow(str(config.th_num))}"
              f"  {color.green('Randomize:')} {color.yellow(str(config.randomize))}")
        if config.proxy_rotator.enabled:
            print(f"{color.green('Proxies:')} {color.yellow(str(len(config.proxy_rotator.proxies)))}")
        print()

        # Launch scanning process
        p = Process(target=Core(config).run)
        if common.os_check() == 'windows':
            p.run()
        else:
            p.start()
            p.join()

    except KeyboardInterrupt:
        logger.warning('Ctrl + c was pressed')
        try:
            p.kill()
        except Exception:
            pass
        sys.exit()

    except Exception as e:
        logger.error(e)
        print(f"{color.red('error occurred, see the')} {color.yellow('log.txt')} "
              f"{color.red('for more information.')}")
        sys.exit()


if __name__ == '__main__':
    run()
