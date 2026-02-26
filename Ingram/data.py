"""Data flow management"""
import hashlib
import os
import random
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Lock, RLock, Thread

from loguru import logger

from .utils import common
from .utils import timer
from .utils import net


@common.singleton
class Data:

    def __init__(self, config):
        self.config = config
        self.create_time = timer.get_time_stamp()
        self.runned_time = 0
        self.taskid = hashlib.md5((self.config.in_file + self.config.out_dir).encode('utf-8')).hexdigest()

        self.total = 0
        self.done = 0
        self.found = 0

        self.total_lock = Lock()
        self.found_lock = Lock()
        self.done_lock = Lock()
        self.vulnerable_lock = Lock()
        self.not_vulneralbe_lock = Lock()

        # Enhanced dashboard tracking
        self.recent_vulns = deque(maxlen=5)  # last 5 vulnerability findings
        self.recent_vulns_lock = Lock()
        self.device_counts = {}  # product -> count of vulnerabilities
        self.device_counts_lock = Lock()
        self.rate_samples = deque(maxlen=20)  # (timestamp, done_count) for rate calc
        self.rate_samples_lock = Lock()
        self.current_target = ''  # IP currently being scanned
        self.current_target_lock = Lock()
        self.last_vuln_url = ''  # last vulnerable target as http URL
        self.last_vuln_url_lock = Lock()
        self.target_start_time = 0.0  # when current target scan began
        self.last_target_time = 0.0   # how long last target took (seconds)
        self.total_target_time = 0.0  # cumulative scan time for avg calc
        self.target_time_lock = Lock()
        self.is_resumed = False       # whether scan was resumed from previous state

        self.preprocess()

    def _load_state_from_disk(self):
        """Load previous run state if it exists"""
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                if line := f.readline().strip():
                    _done, _found, _runned_time = line.split(',')
                    self.done = int(_done)
                    self.found = int(_found)
                    self.runned_time = float(_runned_time)
                    if self.done > 0:
                        self.is_resumed = True

    def clear_previous_state(self):
        """Clear previous run state to start fresh"""
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            os.remove(state_file)
        # Clear results files
        vuln_file = os.path.join(self.config.out_dir, self.config.vulnerable)
        not_vuln_file = os.path.join(self.config.out_dir, self.config.not_vulnerable)
        for f in [vuln_file, not_vuln_file]:
            if os.path.exists(f):
                open(f, 'w').close()
        self.done = 0
        self.found = 0
        self.runned_time = 0
        self.is_resumed = False

    def _cal_total(self):
        """计算目标总数"""
        with open(self.config.in_file, 'r') as f:
            for line in f:
                if (strip_line := line.strip()) and not line.startswith('#'):
                    self.add_total(net.get_ip_seg_len(strip_line))

    def _generate_ip(self):
        """Generate IPs with optional randomization to avoid sequential scanning"""
        current, remain = 0, []
        should_randomize = getattr(self.config, 'randomize', False)
        with open(self.config.in_file, 'r') as f:
            if self.done:
                for line in f:
                    if (strip_line := line.strip()) and not line.startswith('#'):
                        current += net.get_ip_seg_len(strip_line)
                        if current == self.done:
                            break
                        elif current < self.done:
                            continue
                        else:
                            ips = net.get_all_ip(strip_line)
                            remain = ips[(self.done - current):]
                            break
                for ip in remain:
                    yield ip

            if should_randomize:
                # Buffer and shuffle IPs in chunks to avoid sequential scanning patterns
                CHUNK_SIZE = 10000
                chunk = []
                for line in f:
                    if (strip_line := line.strip()) and not line.startswith('#'):
                        for ip in net.get_all_ip(strip_line):
                            chunk.append(ip)
                            if len(chunk) >= CHUNK_SIZE:
                                random.shuffle(chunk)
                                for ip_item in chunk:
                                    yield ip_item
                                chunk = []
                if chunk:
                    random.shuffle(chunk)
                    for ip_item in chunk:
                        yield ip_item
            else:
                for line in f:
                    if (strip_line := line.strip()) and not line.startswith('#'):
                        for ip in net.get_all_ip(strip_line):
                            yield ip

    def preprocess(self):
        """预处理"""
        # 打开记录结果的文件
        self.vulnerable = open(os.path.join(self.config.out_dir, self.config.vulnerable), 'a')
        self.not_vulneralbe = open(os.path.join(self.config.out_dir, self.config.not_vulnerable), 'a')

        self._load_state_from_disk()

        cal_thread = Thread(target=self._cal_total)
        cal_thread.start()

        self.ip_generator = self._generate_ip()
        cal_thread.join()

    def add_total(self, item=1):
        if isinstance(item, int):
            with self.total_lock:
                self.total += item
        elif isinstance(item, list):
            with self.total_lock:
                self.total += sum(item)

    def add_found(self, item=1):
        if isinstance(item, int):
            with self.found_lock:
                self.found += item
        elif isinstance(item, list):
            with self.found_lock:
                self.found += sum(item)

    def add_done(self, item=1):
        if isinstance(item, int):
            with self.done_lock:
                self.done += item
        elif isinstance(item, list):
            with self.done_lock:
                self.done += sum(item)
        # Record sample for scan rate calculation
        with self.rate_samples_lock:
            self.rate_samples.append((time.time(), self.done))

    def add_vulnerable(self, item):
        with self.vulnerable_lock:
            self.vulnerable.writelines(','.join(item) + '\n')
            self.vulnerable.flush()
        # Track for dashboard
        with self.recent_vulns_lock:
            self.recent_vulns.append(item)
        if len(item) >= 2:
            ip, port = item[0], item[1]
            scheme = 'https' if str(port) in ('443', '8443') else 'http'
            with self.last_vuln_url_lock:
                self.last_vuln_url = f"{scheme}://{ip}:{port}"
        if len(item) >= 3:
            product = item[2].split('-')[0] if '-' in item[2] else item[2]
            with self.device_counts_lock:
                self.device_counts[product] = self.device_counts.get(product, 0) + 1

    def add_not_vulnerable(self, item):
        with self.not_vulneralbe_lock:
            self.not_vulneralbe.writelines(','.join(item) + '\n')
            self.not_vulneralbe.flush()

    def record_running_state(self):
        # 每隔 20 个记录一下当前运行状态
        if self.done % 20 == 0:
            with open(os.path.join(self.config.out_dir, f".{self.taskid}"), 'w') as f:
                f.write(f"{str(self.done)},{str(self.found)},{self.runned_time + timer.get_time_stamp() - self.create_time}")

    def __del__(self):
        try:  # if dont use try, sys.exit() may cause error
            self.record_running_state()
            self.vulnerable.close()
            self.not_vulneralbe.close()
        except Exception as e:
            logger.error(e)


@common.singleton
class SnapshotPipeline:

    def __init__(self, config):
        self.config = config
        self.var_lock = RLock()
        self.pipeline = Queue(self.config.th_num * 2)
        self.workers = ThreadPoolExecutor(self.config.th_num)
        self.snapshots_dir = os.path.join(self.config.out_dir, self.config.snapshots)
        self.done = len(os.listdir(self.snapshots_dir))
        self.task_count = 0
        self.task_count_lock = Lock()

    def put(self, msg):
        """放入一条消息
        Queue 自代锁，且会阻塞
        params:
        - msg: (poc.exploit, results)
        """
        self.pipeline.put(msg)

    def empty(self):
        return self.pipeline.empty()

    def get(self):
        return self.pipeline.get()

    def get_done(self):
        with self.var_lock:
            return self.done

    def add_done(self, num=1):
        with self.var_lock:
            self.done += num

    def _snapshot(self, exploit_func, results):
        """利用 poc 的 exploit 方法获取 results 处的资源
        params:
        - exploit_func: pocs 路径下每个 poc 的 exploit 方法
        - results: poc 的 verify 验证为真时的返回结果
        """
        if res := exploit_func(results):
            self.add_done(res)
        with self.task_count_lock:
            self.task_count -= 1

    def process(self, core):
        while not core.finish():
            exploit_func, results = self.get()
            self.workers.submit(self._snapshot, exploit_func, results)
            with self.task_count_lock:
                self.task_count += 1
            time.sleep(.1)