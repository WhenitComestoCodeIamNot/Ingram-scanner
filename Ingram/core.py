import os
from collections import defaultdict
from threading import Thread

import gevent
from loguru import logger
from gevent.pool import Pool as geventPool

from .data import Data, SnapshotPipeline
from .pocs import get_poc_dict
from .utils import color
from .utils import common
from .utils import fingerprint
from .utils import port_scan
from .utils import status_bar
from .utils import timer
from .utils.evasion import get_random_headers
from .utils.rtsp_probe import rtsp_probe, rtsp_try_creds, RTSP_PORTS


@common.singleton
class Core:

    def __init__(self, config):
        self.config = config
        self.data = Data(config)
        self.snapshot_pipeline = SnapshotPipeline(config)
        self.poc_dict = get_poc_dict(self.config)
        # Get the RTSP POC if available
        self.rtsp_poc = self.poc_dict.get('__rtsp__', [])

    def finish(self):
        return (self.data.done >= self.data.total) and (self.snapshot_pipeline.task_count <= 0)

    def report(self):
        """report the results"""
        results_file = os.path.join(self.config.out_dir, self.config.vulnerable)
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                items = [l.strip().split(',') for l in f if l.strip()]

            if items:
                results = defaultdict(lambda: defaultdict(lambda: 0))
                for i in items:
                    dev, vul = i[2].split('-')[0], i[-1]
                    results[dev][vul] += 1
                results_sum = len(items)
                results_max = max([val for vul in results.values() for val in vul.values()])

                print('\n')
                print('-' * 19, 'REPORT', '-' * 19)
                for dev in results:
                    vuls = [(vul_name, vul_count) for vul_name, vul_count in results[dev].items()]
                    dev_sum = sum([i[1] for i in vuls])
                    print(color.red(f"{dev} {dev_sum}", 'bright'))
                    for vul_name, vul_count in vuls:
                        block_num = int(vul_count / results_max * 25)
                        print(color.green(f"{vul_name:>18} | {'▥' * block_num} {vul_count}"))
                print(color.yellow(f"{'sum: ' + str(results_sum):>46}", 'bright'), flush=True)
                print('-' * 46)
                print('\n')

    def _scan(self, target):
        """
        params:
        - target: ip or ip:port
        """
        items = target.split(':')
        ip = items[0]
        ports = [items[1], ] if len(items) > 1 else self.config.ports

        # Rate limiting per target
        self.config.rate_limiter.wait(ip)

        # Port scanning
        for port in ports:
            if port_scan(ip, port, self.config.timeout):
                logger.info(f"{ip} port {port} is open")
                # Fingerprint
                if product := fingerprint(ip, port, self.config):
                    logger.info(f"{ip}:{port} is {product}")
                    verified = False
                    # poc verify & exploit
                    for poc in self.poc_dict[product]:
                        # Rate limit between POC attempts
                        self.config.rate_limiter.wait(ip)
                        if results := poc.verify(ip, port):
                            verified = True
                            self.data.add_found()
                            self.data.add_vulnerable(results[:6])
                            # snapshot
                            if not self.config.disable_snapshot:
                                self.snapshot_pipeline.put((poc.exploit, results))
                    if not verified:
                        self.data.add_not_vulnerable([ip, str(port), product])

        # RTSP probing (separate from HTTP fingerprinting)
        if not getattr(self.config, 'disable_rtsp', False) and self.rtsp_poc:
            for rtsp_port in RTSP_PORTS:
                rtsp_port_str = str(rtsp_port)
                # Skip if this port was already in the HTTP scan list
                if rtsp_port_str in [str(p) for p in ports]:
                    continue
                if port_scan(ip, rtsp_port_str, self.config.timeout):
                    logger.info(f"{ip} RTSP port {rtsp_port} is open")
                    self.config.rate_limiter.wait(ip)
                    for poc in self.rtsp_poc:
                        if results := poc.verify(ip, rtsp_port):
                            self.data.add_found()
                            self.data.add_vulnerable(results[:6])
                            break

        self.data.add_done()
        self.data.record_running_state()

    def run(self):
        logger.info(f"running at {timer.get_time_formatted()}")
        logger.info(f"config is {self.config}")
        logger.info(f"scan speed: {self.config.scan_speed}, threads: {self.config.th_num}, randomize: {self.config.randomize}")

        if self.config.proxy_rotator.enabled:
            logger.info(f"proxy rotation enabled with {len(self.config.proxy_rotator.proxies)} proxies")

        try:
            # Status bar
            self.status_bar_thread = Thread(target=status_bar, args=[self, ], daemon=True)
            self.status_bar_thread.start()
            # Snapshot pipeline
            if not self.config.disable_snapshot:
                self.snapshot_pipeline_thread = Thread(target=self.snapshot_pipeline.process, args=[self, ], daemon=True)
                self.snapshot_pipeline_thread.start()
            # Scanning
            scan_pool = geventPool(self.config.th_num)
            for ip in self.data.ip_generator:
                scan_pool.start(gevent.spawn(self._scan, ip))
            scan_pool.join()

            self.status_bar_thread.join()

            self.report()

        except KeyboardInterrupt:
            pass

        except Exception as e:
            logger.error(e)
