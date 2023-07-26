#!/usr/bin/env python3
#
# Copyright (C) 2023 Kawashima Teruaki <ktmizugaki@gmail.com>
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.
#

### hash_helper
import hashlib
import io
import threading
import queue

def hash_file(path, m, blocksize=64*1024):
    if type(m) is str:
        m = hashlib.new(m, usedforsecurity=False)
    with io.open(path, "rb") as f:
        while True:
            d = f.read(blocksize)
            if not d:
                break
            m.update(d)
    return m.hexdigest()

class AsyncWorker:
    def __init__(self, index):
        self.index = index
        self.q = queue.Queue(16)
        self.thread = threading.Thread(target=self.run, args=(self.q,), name=f"Worker#{index}", daemon=True)
        self.thread.start()

    def put(self, task):
        self.q.put(task)

    def terminate(self):
        q = self.q
        self.q = None
        if q is not None:
            q.put(None)

    def run(self, q):
        while True:
            task = q.get()
            if task is None:
                q.task_done()
                break
            task()
            q.task_done()

class AsyncPool:
    DEFAULT_WORKERS = 4
    def __init__(self, num_workers=DEFAULT_WORKERS):
        self.lock = threading.Lock()
        self.workers = [None]*num_workers
        self.worker_class = AsyncWorker
        self.index = 0

    def obtain(self):
        with self.lock:
            if self.workers is None:
                raise AssertionError('pool is terminated')
            index = self.index
            self.index = (self.index+1)%len(self.workers)
            if self.workers[index] is None:
                self.workers[index] = self.worker_class(index)
            return self.workers[index]

    def terminate(self):
        with self.lock:
            if self.workers is None:
                return
            workers = self.workers
            self.workers = None
        for worker in workers:
            if worker is not None:
                worker.terminate()

class AsyncHash:
    _default_pool = None
    @classmethod
    def default_pool(cls):
        if cls._default_pool is None:
            cls._default_pool = AsyncPool()
        return cls._default_pool

    def __init__(self, m, pool=None):
        pool = pool or self.default_pool()
        if type(m) is str:
            m = hashlib.new(m, usedforsecurity=False)
        self._m = m
        self.name = m.name
        self._q = queue.Queue(4)
        self._worker = pool.obtain()

    def _process(self):
        q = self._q
        data = q.get()
        try:
            self._m.update(data)
        finally:
            q.task_done()

    def update(self, data):
        self._q.put(data)
        self._worker.put(self._process)

    def digest(self):
        self._q.join()
        return self._m.digest()

    def hexdigest(self):
        self._q.join()
        return self._m.hexdigest()

class MultiHash:
    @staticmethod
    def to_m(m, wantasync=False):
        if type(m) == str:
            m = hashlib.new(m, usedforsecurity=False)
        if wantasync:
            return AsyncHash(m)
        else:
            return m

    def __init__(self, *ms, wantasync=False):
        self.ms = [self.to_m(m, wantasync=wantasync) for m in ms]
        self.name = ",".join([m.name for m in self.ms])

    def update(self, data):
        if type(data) is not bytes:
            raise TypeError('data must be bytes')
        for m in self.ms:
            m.update(data)

    def digest(self):
        digest = {}
        for m in self.ms:
            digest[m.name] = m.digest()
        return digest

    def hexdigest(self):
        digest = {}
        for m in self.ms:
            digest[m.name] = m.hexdigest()
        return digest
