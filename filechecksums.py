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

class PathMap:
    @classmethod
    def normalize(cls, path):
        path = os.path.normpath(path)
        if os.sep != '/':
            path = path.replace(os.sep, '/')
        return path

    @classmethod
    def to_real(cls, path, base_dir):
        if base_dir == "":
            raise ValueError(f"invalid base_dir: {base_dir}")
        if base_dir is None:
           return path
        return os.path.join(base_dir, path).removeprefix("./")

    @classmethod
    def to_relative(cls, path, base_dir):
        if base_dir == "" or base_dir is None:
            raise ValueError(f"invalid base_dir: {base_dir}")
        path = os.path.relpath(path, base_dir)
        if path.startswith("../"):
            raise Exception(f"path {path} is not under {base_dir}")
        return path

class FileLister:
    def __init__(self, dir, callback):
        self.dir = PathMap.normalize(dir)
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
#from pathutil import PathUtil, PathMap, FileLister, FileListerCallback

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

    def mappath(self, path):
        return PathMap.to_relative(PathMap.normalize(path), self.lister.dir)

    def should_recur(self, dir, parent_path):
        path = self.mappath(dir.path)
        if self.config.should_exclude(path+"/"):
            return False
        return True

    def should_emit(self, file, parent_path):
        path = self.mappath(file.path)
        if self.config.should_exclude(path):
            return False
        if not self.config.should_include(path):
            return False
        return True

    def found(self, file, parent_path):
        self.files.append(self.mappath(file.path))

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
        return (self.mappath(file.path) for file, dir in self.lister)

### filechecksums.store

import re
import os
import bisect
#from pathutil import PathMap
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

    def __init__(self, values, base_dir=None):
        super().__init__(values)
        self.base_dir = base_dir
        self.state = self.STATE_NEW
        self.path = self.values.get("path", None)
        self.size = self.values.get("size", -1)
        self.mtime = self.values.get("mtime", 0)

    def __eq__(self, other):
        return self is other or self.path == other.path

    def __lt__(self, other):
        return self.path < other.path

    @classmethod
    def from_path(cls, path, base_dir=None):
        entry = cls({}, base_dir)
        entry.add("path", path)
        try:
            stat = os.stat(entry.realpath())
            entry.add("size", stat.st_size)
            entry.add("mtime", int(stat.st_mtime))
        except IOError:
            pass
        return entry

    @classmethod
    def from_ltsv(cls, line, base_dir=None):
        instance = super().from_ltsv(line)
        instance.base_dir = base_dir
        return instance

    def realpath(self):
        return PathMap.to_real(self.path, self.base_dir)

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
        base_dir = PathMap.normalize(os.path.dirname(path))
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
                entry = FCSEntry.from_ltsv(line, base_dir)
                entry.state = FCSEntry.STATE_LOADED
                instance.add(entry)
        return instance

    @classmethod
    def load_config(cls, path, readonly=True):
        base_dir = PathMap.normalize(os.path.dirname(path))
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

### filechecksums.cmd
from abc import ABCMeta, abstractmethod
import os
import sys
import argparse
#from pathutil import PathMap

class StorePathAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if os.path.isdir(values):
            values = os.path.join(values, self.default)
        setattr(namespace, self.dest, values)

class FCSCmdBase(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def name(cls):
        raise NotImplementedError("not implemented")

    @classmethod
    def isself(cls, name):
        return cls.name() == name

    @classmethod
    @abstractmethod
    def argparser(cls):
        raise NotImplementedError("not implemented")

    @classmethod
    def add_verbose_arguments(cls, argparser, default=0):
        argparser.add_argument(
            "--verbose", "-v", dest="verbose",
            action="count", default=default, help="output more message")
        argparser.add_argument(
            "--quiet", "-q", dest="quiet",
            action="count", default=0, help="output less message")

    @classmethod
    def add_file_arguments(cls, argparser, default=FileCheckSums.DEFAULT_STORE):
        argparser.add_argument(
            "filename", metavar="file", nargs="?",
            action=StorePathAction, default=default)

    @classmethod
    def usage(cls):
        return cls.argparser().format_usage()

    def set_verbose(self, args):
        self.verbose = args.verbose - args.quiet

    def __init__(self, argv):
        self.ui = lambda name, data: None
        self.verbose = 0

    @abstractmethod
    def __call__(self):
        raise NotImplementedError("not implemented")

class FCSCmdInit(FCSCmdBase):
    _argparser = None

    @classmethod
    def name(cls):
        return "init"

    @classmethod
    def argparser(cls):
        if cls._argparser is None:
            cls._argparser = argparse.ArgumentParser(
                prog = "init",
                description="initialize file check file")
            cls.add_verbose_arguments(cls._argparser)
            cls._argparser.add_argument(
                "--include", "-i", dest="includes", metavar="pattern",
                action="append", help="pattern of files to be included")
            cls._argparser.add_argument(
                "--exclude", "-x", dest="excludes", metavar="pattern",
                action="append", help="pattern of files to be excluded")
            cls._argparser.add_argument(
                "--alg", "-g", dest="algs", metavar="alg",
                action="append", help="algorithms of checksum. defualt is md5 and sha256")
            cls._argparser.add_argument(
                "--force", "-f", dest="force",
                action="store_true", help="overwrite existing file")
            cls.add_file_arguments(cls._argparser)
        return cls._argparser

    def __init__(self, argv):
        super().__init__(argv)
        args = self.argparser().parse_args(argv)
        self.set_verbose(args)
        if args.algs is None:
            args.algs = ["md5", "sha256"]
        self.config = FCSHeader.from_args(args)
        self.force = args.force
        self.filename = args.filename

    def __call__(self):
        if os.path.isdir(self.filename):
            self.ui("init.directory", self.filename)
            sys.exit(2)
        if os.path.lexists(self.filename):
            if self.force:
                self.ui("init.forceinit", self.filename)
            elif FileCheckSums.is_fcsstore(self.filename):
                self.ui("init.conflict", self.filename)
                sys.exit(2)
            else:
                self.ui("init.invalid", self.filename)
                sys.exit(2)
        fcs = FileCheckSums(self.filename)
        fcs.config = self.config
        fcs.save()
        self.ui("init.initialized", str(self.filename))

class FCSCmdConfig(FCSCmdBase):
    _argparser = None

    @classmethod
    def name(cls):
        return "config"

    @classmethod
    def argparser(cls):
        if cls._argparser is None:
            cls._argparser = argparse.ArgumentParser(
                prog = "config",
                description="show or change configuration")
            cls._argparser.add_argument(
                "--add-include", dest="add_includes", metavar="pattern",
                action="append", help="pattern of files to be included")
            cls._argparser.add_argument(
                "--remove-include", dest="remove_includes", metavar="pattern",
                action="append", help="pattern of files to be included")
            cls._argparser.add_argument(
                "--add-exclude", dest="add_excludes", metavar="pattern",
                action="append", help="pattern of files to be excluded")
            cls._argparser.add_argument(
                "--remove-exclude", dest="remove_excludes", metavar="pattern",
                action="append", help="pattern of files to be excluded")
            cls._argparser.add_argument(
                "--add-alg", dest="add_algs", metavar="alg",
                action="append", help="algorithms of checksum")
            cls._argparser.add_argument(
                "--remove-alg", dest="remove_algs", metavar="alg",
                action="append", help="algorithms of checksum")
            cls._argparser.add_argument(
                "--dry-run", "-n", dest="dry_run",
                action="store_true")
            cls.add_file_arguments(cls._argparser)
        return cls._argparser

    def __init__(self, argv):
        super().__init__(argv)
        args = self.argparser().parse_args(argv)
        self.operations = []
        for p in args.add_includes or []:
            self.operations.append(("add", "include", p))
        for p in args.remove_includes or []:
            self.operations.append(("remove", "include", p))
        for p in args.add_excludes or []:
            self.operations.append(("add", "exclude", p))
        for p in args.remove_excludes or []:
            self.operations.append(("remove", "exclude", p))
        for p in args.add_algs or []:
            self.operations.append(("add", "alg", p))
        for p in args.remove_algs or []:
            self.operations.append(("remove", "alg", p))
        self.dry_run = args.dry_run
        self.filename = args.filename

    def __call__(self):
        readonly = self.dry_run or not self.operations
        fcs = FileCheckSums.load_config(self.filename, readonly=readonly)
        for op, name, value in self.operations:
            if op == "add":
                fcs.config.add(name, value)
                continue
            if op == "remove":
                values = fcs.config.get(name)
                if values is None or len(values) == 0:
                    continue
                if type(values) is list:
                    try:
                        values.remove(value)
                        fcs.config.set(name, values)
                    except ValueError:
                        self.ui("config.notexist", (name, value))
                elif values == value:
                    try:
                        del fcs.config.values[name]
                    except KeyError:
                        pass
                continue
        if not readonly:
            fcs.save_config()

        self.ui("config.begin", str(self.filename))
        for k, v in fcs.config:
            if k == "magic":
                continue
            self.ui("config.show", (k, v))
        self.ui("config.end", str(self.filename))

class UpdateStat:
    def __init__(self):
        self.add = 0
        self.update = 0
        self.downdate = 0
        self.newalg = 0
        self.remove = 0

    def format_summary(self):
        return f"""
add...{self.add}
update...{self.update}
downdate...{self.downdate}
remove...{self.remove}
"""

class FCSCmdUpdate(FCSCmdBase):
    _argparser = None

    @classmethod
    def name(cls):
        return "update"

    @classmethod
    def argparser(cls):
        if cls._argparser is None:
            cls._argparser = argparse.ArgumentParser(
                prog = "update",
                description="add/update file records")
            cls.add_verbose_arguments(cls._argparser, default=1)
            cls._argparser.add_argument(
                "--update", dest="update",
                action="store_true", help="recalc existing files if newer")
            cls._argparser.add_argument(
                "--downdate", dest="downdate",
                action="store_true", help="recalc existing files if older")
            cls._argparser.add_argument(
                "--full", dest="full",
                action="store_true", help="recalc existing files if chanegd. same as --update --downdate")
            cls._argparser.add_argument(
                "--prune", dest="prune",
                action="store_true", help="remove non-existing files")
            cls._argparser.add_argument(
                "--dry-run", "-n", dest="dry_run",
                action="store_true")
            cls.add_file_arguments(cls._argparser)
        return cls._argparser

    def __init__(self, argv):
        super().__init__(argv)
        args = self.argparser().parse_args(argv)
        self.set_verbose(args)
        self.update = (args.update or args.full)
        self.downdate = (args.downdate or args.full)
        self.prune = args.prune
        self.dry_run = args.dry_run
        self.filename = args.filename
        self.stat = UpdateStat()

    def should_recalc(self, f, e, fcs):
        if e is None:
            return 'new'
        if self.update and f.mtime > e.mtime:
            return 'update'
        if self.downdate and f.mtime < e.mtime:
            return 'downdate'
        if not all(alg in e for alg in fcs.config.algs()):
            return 'newalg'
        return None

    def update_stat(self, reason):
        if reason == 'new':
            self.stat.add += 1
        elif reason == 'update':
            self.stat.update += 1
        elif reason == 'downdate':
            self.stat.downdate += 1
        elif reason == 'newalg':
            self.stat.newalg += 1

    def process_file(self, f, e, fcs):
        reason = self.should_recalc(f, e, fcs)
        if reason:
            self.update_stat(reason)
            if reason == 'new':
                self.ui("update.add", (reason, f.path))
            else:
                self.ui("update.recalc", (reason, f.path))
            if not self.dry_run:
                hexdigests = hash_file(f.path, MultiHash(*fcs.config.algs(), wantasync=f.size >= 1024*1024))
                skip = False
                if reason == 'newalg':
                    skip = any(alg in e and e.get(alg) != hexdigests.get(alg) for alg in fcs.config.algs())
                if skip:
                    self.ui("update.fail", f.path)
                else:
                    for alg in fcs.config.algs():
                        f.add(alg, hexdigests.get(alg))
                    if e is None:
                        fcs.add(f)
                    else:
                        e.merge(f)
        else:
            if e is not None:
                self.ui("update.skip", f.path)

        if e is None:
            f.state = FCSEntry.STATE_CHANGED
        else:
            e.state = FCSEntry.STATE_CHANGED

    def __call__(self):
        fcs = FileCheckSums.load(self.filename, readonly=self.dry_run)
        opts = FCSHeader({})
        opts.merge(fcs.config)
        opts.add("exclude", "/"+os.path.basename(self.filename))
        base_dir = PathMap.normalize(os.path.dirname(fcs.path))
        files = FCSFiles(base_dir, opts)
        self.ui("update.listfiles.begin", base_dir)
        files.build()
        self.ui("update.listfiles.end", base_dir)
        for file in files:
            f = FCSEntry.from_path(file, base_dir)
            e = fcs.get(f.path)
            self.process_file(f, e, fcs)

        if self.prune:
            removed = [f for f in fcs.files if f.state == FCSEntry.STATE_LOADED]
            for f in removed:
                self.stat.remove += 1
                self.ui("update.remove", f.path)
                if not self.dry_run:
                    fcs.remove(f)

        if not self.dry_run:
            fcs.save()

        self.ui("update.stat", self.stat)

class VerifyStat:
    def __init__(self):
        self.ok = 0
        self.ng = 0
        self.changed = 0
        self.invalid = 0

    def format_summary(self):
        return f"""
ok...{self.ok}
NG...{self.ng}
changed...{self.changed}
invalid...{self.invalid}
"""

class FCSCmdVerify(FCSCmdBase):
    _argparser = None

    @classmethod
    def name(cls):
        return "verify"

    @classmethod
    def argparser(cls):
        if cls._argparser is None:
            cls._argparser = argparse.ArgumentParser(
                prog = "verify",
                description="verify file records")
            cls.add_verbose_arguments(cls._argparser, default=1)
            cls.add_file_arguments(cls._argparser)
        return cls._argparser

    def __init__(self, argv):
        super().__init__(argv)
        args = self.argparser().parse_args(argv)
        self.set_verbose(args)
        self.filename = args.filename
        self.stat = VerifyStat()

    def update_stat(self, reason):
        if reason == 'ok':
            self.stat.ok += 1
        elif reason == 'ng':
            self.stat.ng += 1
        elif reason == 'changed':
            self.stat.changed += 1
        elif reason == 'invalid':
            self.stat.ng += 1
            self.stat.invalid += 1

    def process_file(self, e, f, fcs):
        path = f.path
        if not os.path.isfile(path) or os.path.islink(path):
            self.update_stat('invalid')
            self.ui("verify.invalid_file", f)
            return

        if f.size == 0 and f.mtime == 0:
            self.update_stat('invalid')
            self.ui("verify.invalid_file", f)
            return

        self.ui("verify.start_file", e)
        if self.changed(e, f):
            self.update_stat('changed')

        reason = 'ok'
        try:
            algs = fcs.config.algs()
            hexdigests = hash_file(path, MultiHash(*algs, wantasync=f.size >= 1024*1024))
            if any(hexdigests.get(alg) != e.get(alg) for alg in algs):
                reason = 'ng'
        except IOError:
            reason = 'invalid'
        except Exception:
            reason = 'ng'

        self.update_stat(reason)
        if reason == 'ok':
            result = 'ok'
        else:
            result = "NG"
        self.ui("verify.end_file", (f, result))

    def __call__(self):
        fcs = FileCheckSums.load(self.filename)
        try:
            for e in fcs.files:
                f = FCSEntry.from_path(e.realpath())
                self.process_file(e, f, fcs)

        finally:
            self.ui("verify.stat", self.stat)

    def changed(self, e, f):
        if e is None or f is None:
            return True
        if e.mtime != f.mtime:
            return True
        if e.size != f.size:
            return True
        return False

### main
import traceback
import sys

class FCSConsoleUI:
    def __init__(self, verbose=0):
        self.verbose = verbose

    def log(self, *args):
        print(*args, file=sys.stderr)

    def output(self, *args):
        print(*args, file=sys.stdout)

    def oninit(self, name, data):
        if name == "init.initialized":
            self.log(f"created file checksum store: {data}")
            return
        if name == "init.directory":
            self.log(f"'{data}' is directory")
            return
        if name == "init.forceinit":
            self.log(f"overwrite '{data}'")
            return
        if name == "init.conflict":
            self.log(f"'{data}' is already initialized")
            return
        if name == "init.invalid":
            self.log(f"'{data}' exists and is not file checksum store")
            return

    def onconfig(self, name, data):
        if name == "config.begin":
            self.output(f"{data}:")
            return
        if name == "config.end":
            self.output()
            return
        if name == "config.show":
            self.output(f"--{data[0]} {data[1]}")
            return

    def onupdate(self, name, data):
        if name == "update.listfiles.begin":
            sys.stdout.write("Building file list..")
        if name == "update.listfiles.end":
            sys.stdout.write("\r                        \r")
        if name == "update.add":
            if self.verbose >= 1:
                self.output(f"add {data[1]}")
            return
        if name == "update.recalc":
            if self.verbose >= 1:
                self.output(f"recalc {data[1]}")
            return
        if name == "update.skip":
            if self.verbose >= 2:
                self.output(f"skip {data}")
            return
        if name == "update.remove":
            if self.verbose >= 1:
                self.output(f"remove {data}")
            return
        if name == "update.fail":
            if self.verbose >= 1:
                self.output(f"failed {data}")
            return
        if name == "update.stat":
            self.output(data.format_summary().rstrip("\n"))
            return

    def onverify(self, name, data):
        if name == "verify.invalid_file":
            if self.verbose >= 1:
                self.output(f"not file: {data.path}")
            return
        if name == "verify.start_file":
            if self.verbose >= 1:
                sys.stdout.write(f"verify {data.path}...")
            return
        if name == "verify.end_file":
            if self.verbose >= 1:
                self.output(f"{data[1]}")
            elif data[1] == 'NG':
                self.output(f"{data[0].path}...{data[1]}")
            return
        if name == "verify.stat":
            self.output(data.format_summary().rstrip("\n"))
            return

    def onhelp(self, name, data):
        if name == "help.usage":
            if data[1] is None:
                self.output(data[0])
            else:
                self.log(data[1]+"\n")
                self.log(data[0])
            return

    def __call__(self, name, data):
        if name.startswith("init."):
            self.oninit(name, data)
        if name.startswith("config."):
            self.onconfig(name, data)
        if name.startswith("update."):
            self.onupdate(name, data)
        if name.startswith("verify."):
            self.onverify(name, data)
        if name.startswith("help."):
            self.onhelp(name, data)

class FCSCmdHelp(FCSCmdBase):
    _argparser = None

    @classmethod
    def name(cls):
        return "help"

    @classmethod
    def argparser(cls):
        if cls._argparser is None:
            cls._argparser = argparse.ArgumentParser(
                prog = "help",
                description="show this help message")
            cls._argparser.add_argument(
                "cmdname", metavar="cmd", nargs="?")
        return cls._argparser

    def __init__(self, argv):
        super().__init__(argv)
        (args, _rest) = self.argparser().parse_known_args(argv)
        self.cmdname = args.cmdname

    def __call__(self):
        if self.cmdname:
            cls = get_cmdcls(self.cmdname)
            if cls is None:
                self.unknown_cmd(self.cmdname)

            cmd = cls(["-h"])
            cmd.ui = self.ui
            cmd()

        else:
            self.usage()

    def show_usage(self, message=None):
        usage = "Available commands:\n"
        for cls in cmdclses:
            cmdusage = cls.usage()
            usage += "  "+cmdusage.removeprefix("usage: ")

        self.ui("help.usage", (usage.rstrip("\n"), message))

    def unknown_cmd(self, cmdname):
        self.show_usage(f"Unknown command: {cmdname}")
        sys.exit(2)

    def missing_cmd(self):
        self.show_usage("Missing command")
        sys.exit(2)

cmdclses = [
    FCSCmdHelp,
    FCSCmdInit,
    FCSCmdConfig,
    FCSCmdUpdate,
    FCSCmdVerify,
]

uiclass = FCSConsoleUI

def get_cmdcls(name):
    for cls in cmdclses:
        if cls.isself(name):
            return cls
    return None

def main(argv):
    try:
        if len(argv) < 2:
            help = FCSCmdHelp([])
            help.ui = uiclass(verbose=1)
            help.missing_cmd()
            sys.exit(1)

        cls = get_cmdcls(argv[1])
        if cls is None:
            help = FCSCmdHelp([])
            help.ui = uiclass(verbose=1)
            help.unknown_cmd(argv[1])
            sys.exit(2)

        cmd = cls(argv[2:])
        cmd.ui = uiclass(verbose=cmd.verbose)
        cmd()
        sys.exit(0)

    except KeyboardInterrupt:
        print(file=sys.stderr)
        sys.exit(130)

    except Exception:
        if os.getenv("FCS_DEBUG") == "1":
            limit = None
        else:
            limit = 0
        traceback.print_exc(limit)
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv)
