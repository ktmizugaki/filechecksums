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

### io_helper
import tempfile
import io
import os
import hashlib
#from hash_helper import hash_file

class SafeWriter:
    DIGEST_ALG = "md5"

    def __init__(self, path, mode="w", encoding=None):
        if mode != "w" or mode != "wb":
            ValueError("mode must be \"w\" or \"wb\"")
        if mode == "w":
            if encoding:
                self.encoding = encoding
            else:
                self.encoding = "utf-8"
        else:
            self.encoding = None
        self.path = path
        self.commited = False
        (fd, temppath) = tempfile.mkstemp(prefix=path, dir=".")
        self.tempfile = io.open(fd, mode="wb")
        self.temppath = temppath
        self.hash = hashlib.new(self.DIGEST_ALG, usedforsecurity=False)

    def write(self, data):
        if self.commited:
            raise AssertionError("cannot write after commit")
        if self.encoding:
            data = data.encode(encoding=self.encoding)
        self.hash.update(data)
        return self.tempfile.write(data)

    def commit(self):
        self.tempfile.flush()
        os.fsync(self.tempfile.fileno())
        self.tempfile.close()
        self.commited = True

    def _validate(self):
        expected = self.hash.hexdigest()
        actual = hash_file(self.temppath, self.DIGEST_ALG)
        if actual != expected:
            raise AssertionError(f"failed to write to {self.temppath}")
        return True

    def _remove(self):
        try:
            os.unlink(self.temppath)
        except Exception:
            pass

    def close(self):
        if self.tempfile is None:
            return
        if self.commited and self._validate():
            self.tempfile = None
            try:
                os.replace(self.temppath, self.path)
            except Exception:
                self._remove()
                raise
        else:
            try:
                self.tempfile.close()
            finally:
                self.tempfile = None
                self._remove()
            raise Exception(f"Failed to write {self.path}")

    def __enter__(self):
        if self.tempfile is None:
            return None
        return self

    def __exit__(self, exc, value, tb):
        self.close()

### ltsv
import re

class LTSV:
    UNESCAPE_MAP = {"t":"\t","r":"\r","n":"\n","\\":"\\"}
    ESCAPE_MAP = {v: k for k, v in UNESCAPE_MAP.items()}

    @classmethod
    def escape(cls, value):
        return re.sub(r"(\\|\t|\r|\n)", lambda m: "\\"+cls.ESCAPE_MAP[m.group(1)], value)

    @classmethod
    def unescape(cls, value):
        return re.sub(r"\\(t|r|n|\\)", lambda m: cls.UNESCAPE_MAP[m.group(1)], value)

    @classmethod
    def generate(cls, items):
        line = ""
        if type(items) is dict:
            items = items.items()
        for key, value in items:
            line += "\t"+cls.generate_item(key, value)
        return line[1:]

    @classmethod
    def generate_item(cls, key, value):
        if ":" in key:
            raise KeyError("Key must not contain colon")
        return cls.escape(key)+":"+cls.escape(value)

    @classmethod
    def each(cls, line):
        for item in line.split("\t"):
            yield cls.parse_item(item)

    @classmethod
    def parse(cls, line):
        return dict(cls.each(line))

    @classmethod
    def parse_item(cls, eitem):
        ek, ev = eitem.split(":", 1)
        k = cls.unescape(ek)
        v = cls.unescape(ev)
        return (k, v)

class KeyValue():
    KEY_ORDER = None

    @classmethod
    def is_array(cls, key):
        return False

    @classmethod
    def sort_keys(cls, keys):
        keys = list(keys)
        keys.sort()
        if cls.KEY_ORDER is not None:
            for key in reversed(cls.KEY_ORDER):
                try:
                    keys.remove(key)
                    keys.insert(0, key)
                except ValueError:
                    pass
        return keys

    @classmethod
    def from_ltsv(cls, line):
        instance = cls({})
        line = line.rstrip("\n")
        for k, v in LTSV.each(line):
            instance.add(k, v)
        return instance

    def __init__(self, values):
        if any(":" in key for key in values.keys()):
            raise KeyError("Key must not contain colon")
        self.values = values

    def __contains__(self, key):
        return key in self.values

    def set(self, key, value):
        if self.is_array(key) and type(value) is not list:
            value = [value]
        self.values[key] = value

    def add(self, key, value):
        if value is None:
            value = ""
        else:
            value = str(value)
        if ":" in key:
            raise KeyError("Key must not contain colon")
        if self.is_array(key):
            self.values.setdefault(key, [])
            self.values[key].append(value)
        else:
            self.values[key] = value

    def merge(self, other):
        for (k, v) in other:
            self.add(k, v)

    def get(self, key):
        return self.values.get(key)

    def to_ltsv(self):
        return LTSV.generate(self)

    def __iter__(self):
        keys = self.sort_keys(self.values.keys())
        for k in keys:
            if self.is_array(k):
                for v in self.values[k]:
                    yield (k, v)
            else:
                yield (k, self.values[k])
