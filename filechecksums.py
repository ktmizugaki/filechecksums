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

### pathutil
import os
import re

class PathUtil:
    @classmethod
    def glob_to_pattern(cls, glob):
        if not isinstance(glob, str):
            raise TypeError("glob must be str")
        glob = re.escape(glob)
        pattern = glob.replace("\\*", "[^/]*")
        if pattern.startswith("/"):
            pattern = "^"+pattern
        else:
            pattern = "/"+pattern
        if pattern.endswith("/"):
            pattern = pattern
        else:
            pattern = pattern+"$"
        return pattern

    @classmethod
    def match(cls, glob_or_pattern, path):
        if isinstance(glob_or_pattern, str):
            pattern = re.compile(cls.glob_to_pattern(glob_or_pattern))
        elif isinstance(glob_or_pattern, re.Pattern):
            pattern = glob_or_pattern
        else:
            raise TypeError("glob_or_pattern must be str or Pattern object")
        if type(path) is not str:
            raise TypeError("path must be str")
        if not path.startswith("/"):
            path = "/"+path
        return pattern.search(path) is not None

class FileLister:
    def __init__(self, dir, callback):
        self.dir = dir
        self.callback = callback

    def _walk(self, dir):
        try:
            files = list(file for file in os.scandir(dir) if not file.is_symlink())
        except BaseException as exc:
            self.callback.error(exc, dir)
            return
        for file in files:
            if file.is_dir():
                if self.callback.should_recur(file, dir):
                    for file, dir in self._walk(file.path):
                        yield file, dir
            elif file.is_file():
                if self.callback.should_emit(file, dir):
                    yield file, dir

    def walk(self):
        for file, dir in self._walk(self.dir):
            self.callback.found(file, dir)

    def __iter__(self):
        return self._walk(self.dir)

class FileListerCallback:
    def should_recur(self, dir, parent_path):
        return True
    def should_emit(self, file, parent_path):
        return True
    def found(self, file, parent_path):
        pass
    def error(self, exc, path):
        pass

### filechecksums.config
import re
#from pathutil import PathUtil, FileLister, FileListerCallback

GLOBAL_EXCLUDES=[
    "*.fcsstore",
    ".git/",
    ".svn/",
    "__pycache__/",
    "hiberfil*",
    "pagefile*",
    "System Volume Information/",
    "lost+found/",
    "RECYCLER/",
    "RECYCLE/",
]

CHECKSUM_ALGS = [
    "md5",
    "sha256",
]

class FCSConfig(KeyValue):
    @classmethod
    def is_array(cls, key):
        return \
            key == "include" or \
            key == "exclude" or \
            key == "alg" or \
            super().is_array(key)

    @classmethod
    def from_args(cls, args):
        instance = cls({})
        for p in args.includes or []:
            instance.add("include", p)
        for p in args.excludes or []:
            instance.add("exclude", p)
        for alg in args.algs or []:
            instance.add("alg", alg)
        return instance

    def __init__(self, values):
        super().__init__(values)
        self.exclude_patterns = None
        self.exclude_dirs = None
        self.include_patterns = None
        self.global_excludes = True

    def excludes(self):
        return self.values.get("exclude")

    def includes(self):
        return self.values.get("include")

    def algs(self):
        return self.values.get("alg")

    def prepare_patterns(self):
        excludes = []
        if self.excludes() is not None:
            excludes += self.excludes()
        if self.global_excludes:
            excludes += GLOBAL_EXCLUDES
        if len(excludes) > 0:
            self.exclude_patterns = [re.compile(PathUtil.glob_to_pattern(glob)) for glob in excludes]
            self.exclude_dirs = []
            pattern = re.compile("[^/]+/")
            for glob in excludes:
                if pattern.fullmatch(glob):
                    self.exclude_dirs.append(re.compile(PathUtil.glob_to_pattern(glob)))
        else:
            self.exclude_patterns = None
            self.exclude_dirs = None

        includes = self.includes()
        if includes is not None and len(includes) > 0:
            self.include_patterns = [re.compile(PathUtil.glob_to_pattern(glob)) for glob in includes]
        else:
            self.include_patterns = None

    def is_exclude_dir(self, name):
        if self.exclude_dirs is None:
            return False
        for pattern in self.exclude_dirs:
            if PathUtil.match(pattern, name):
                return True
        return False

    def should_exclude(self, path):
        if self.exclude_patterns is None:
            return False
        for pattern in self.exclude_patterns:
            if PathUtil.match(pattern, path):
                return True
        return False

    def should_include(self, path):
        if self.include_patterns is None:
            return True
        for pattern in self.include_patterns:
            if PathUtil.match(pattern, path):
                return True
        return False

class FCSFiles(FileListerCallback):
    def __init__(self, dir, config):
        self.lister = FileLister(dir, self)
        self.config = config
        self.files = None

    def should_recur(self, dir, parent_path):
        path = dir.path
        if self.config.should_exclude(path+"/"):
            return False
        return True

    def should_emit(self, file, parent_path):
        path = file.path
        if self.config.should_exclude(path):
            return False
        if not self.config.should_include(path):
            return False
        return True

    def found(self, file, parent_path):
        self.files.append(file.path)

    def error(self, exc, path):
        raise

    def build(self):
        self.files = []
        self.config.prepare_patterns()
        self.lister.walk()

    def __iter__(self):
        if self.files is not None:
            return iter(self.files)
        self.config.prepare_patterns()
        return (file.path for file, dir in self.lister)

### filechecksums.store

import re
import os
import bisect
#from filechecksums.config import FCSConfig

class FCSHeader(FCSConfig):
    MAGIC_KEY = "magic"
    MAGIC_VALUE = "FCSSTORE"
    MAGIC = MAGIC_KEY+":"+MAGIC_VALUE
    KEY_ORDER = [MAGIC_KEY]

    def __init__(self, values):
        super().__init__(values)
        self.set(self.MAGIC_KEY, self.MAGIC_VALUE)

    def to_ltsv(self):
        self.set(self.MAGIC_KEY, self.MAGIC_VALUE)
        return super().to_ltsv()

class FCSEntry(KeyValue):
    STATE_NEW = 0
    STATE_LOADED = 1
    STATE_SAVED = 2
    STATE_VERIFIED = 3
    STATE_CHANGED = 4
    KEY_ORDER = ["size", "mtime", "path"]

    @classmethod
    def sort_keys(cls, keys):
        keys = super().sort_keys(keys)
        for key in reversed(CHECKSUM_ALGS):
            try:
                keys.remove(key)
                keys.insert(0, key)
            except ValueError:
                pass
        return keys

    def __init__(self, values):
        super().__init__(values)
        self.state = self.STATE_NEW
        self.path = self.values.get("path", None)
        self.size = self.values.get("size", -1)
        self.mtime = self.values.get("mtime", 0)

    def __eq__(self, other):
        return self is other or self.path == other.path

    def __lt__(self, other):
        return self.path < other.path

    @classmethod
    def from_path(cls, path):
        entry = cls({})
        entry.add("path", path)
        try:
            stat = os.stat(path)
            entry.add("size", stat.st_size)
            entry.add("mtime", int(stat.st_mtime))
        except IOError:
            pass
        return entry

    def merge(self, other):
        self.state = other.state
        super().merge(other)

    def add(self, key, value):
        if key == "path":
            self.path = value
        elif key == "size":
            self.size = int(value)
        elif key == "mtime":
            self.mtime = int(value)
        super().add(key, value)

class FileCheckSums:
    DEFAULT_STORE = ".fcsstore"

    @classmethod
    def is_fcsstore(cls, path):
        if not os.path.isfile(path):
            return False
        try:
            with io.open(path, mode="r", newline="\n") as f:
                line = f.readline()
                return re.match(f"{FCSHeader.MAGIC}(\\t|\\n)", line) is not None
        except IOError:
            pass
        return False

    def __init__(self, path, readonly=False):
        self.path = path
        self.readonly = readonly
        self.config = None
        self.files = []

    @classmethod
    def load(cls, path, readonly=True):
        base_dir = os.path.dirname(path) or "."
        if not cls.is_fcsstore(path):
            raise ValueError(f"path '{path}' is not file checksum store")
        if not readonly and not os.access(path, os.W_OK):
            raise ValueError(f"path '{path}' is not writable")
        if not readonly and not os.access(base_dir, os.W_OK):
            raise ValueError(f"dir '{base_dir}' is not writable")
        instance = cls(path, readonly=readonly)
        with io.open(path, mode="r", newline="\n") as f:
            line = f.readline()
            instance.config = FCSHeader.from_ltsv(line)
            for line in f:
                entry = FCSEntry.from_ltsv(line)
                entry.state = FCSEntry.STATE_LOADED
                instance.add(entry)
        return instance

    @classmethod
    def load_config(cls, path, readonly=True):
        base_dir = os.path.dirname(path) or "."
        if not cls.is_fcsstore(path):
            raise ValueError(f"path '{path}' is not file checksum store")
        if not readonly and not os.access(path, os.W_OK):
            raise ValueError(f"path '{path}' is not writable")
        if not readonly and not os.access(base_dir, os.W_OK):
            raise ValueError(f"dir '{base_dir}' is not writable")
        instance = cls(path, readonly=readonly)
        with io.open(path, mode="r", newline="\n") as f:
            line = f.readline()
            instance.config = FCSHeader.from_ltsv(line)
        return instance

    def save(self):
        if self.readonly:
            raise TypeError("attempt to save readonly instance")
        with SafeWriter(self.path) as f:
            f.write(self.config.to_ltsv()+"\n")
            for entry in self.files:
                f.write(entry.to_ltsv()+"\n")
                entry.state = FCSEntry.STATE_SAVED
            f.commit()

    def save_config(self):
        if self.readonly:
            raise TypeError("attempt to save readonly instance")
        with SafeWriter(self.path) as fout:
            with io.open(self.path, mode="r", newline="\n") as fin:
                # skip old config
                fin.readline()
                # write new config
                fout.write(self.config.to_ltsv()+"\n")
                # copy entries
                for line in fin:
                    fout.write(line)
                fout.commit()

    def get(self, path):
        index = bisect.bisect_left(self.files, FCSEntry({"path": path}))
        if index < len(self.files) and self.files[index].path == path:
            return self.files[index]
        return None

    def add(self, entry):
        bisect.insort(self.files, entry)

    def remove(self, entry):
        self.files.remove(entry)
