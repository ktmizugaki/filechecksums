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

import unittest
import tempfile
import os
import io
import filechecksums as fcs

### hash_helper

class hash_fileTestCase(unittest.TestCase):
    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(suffix='.dat', prefix='fcs_test_') as tmp:
            tmp.write(bytes(range(256)))
            tmp.flush()
            self.assertEqual(fcs.hash_file(tmp.name, 'md5'), 'e2c865db4162bed963bfaa9ef6ac18f0')
            self.assertEqual(fcs.hash_file(tmp.name, 'sha256'), '40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880')

class AsyncPoolTestCase(unittest.TestCase):
    def test_async_pool(self):
        pool = fcs.AsyncPool(num_workers=2)
        worker = pool.obtain()
        self.assertIsNotNone(worker)

    def test_terminate(self):
        pool = fcs.AsyncPool(num_workers=2)
        worker = pool.obtain()
        pool.terminate()
        self.assertIsNone(pool.workers)
        self.assertIsNone(worker.q)
        with self.assertRaises(AttributeError):
            worker.put(lambda : None)

class AsyncHashTestCase(unittest.TestCase):
    def test_async_hash(self):
        data = bytes(range(256))
        m = fcs.AsyncHash('md5')
        m.update(data)
        self.assertEqual(m.digest(), b'\xe2\xc8\x65\xdb\x41\x62\xbe\xd9\x63\xbf\xaa\x9e\xf6\xac\x18\xf0')
        self.assertEqual(m.hexdigest(), 'e2c865db4162bed963bfaa9ef6ac18f0')

class MultiHashTestCase(unittest.TestCase):
    def test_multi_hash(self):
        data = bytes(range(256))
        m = fcs.MultiHash('md5', 'sha256')
        m.update(data)
        digest = m.digest()
        self.assertEqual(digest.get('md5'), b'\xe2\xc8\x65\xdb\x41\x62\xbe\xd9\x63\xbf\xaa\x9e\xf6\xac\x18\xf0')
        self.assertEqual(digest.get('sha256'), b'\x40\xaf\xf2\xe9\xd2\xd8\x92\x2e\x47\xaf\xd4\x64\x8e\x69\x67\x49\x71\x58\x78\x5f\xbd\x1d\xa8\x70\xe7\x11\x02\x66\xbf\x94\x48\x80')
        digest = m.hexdigest()
        self.assertEqual(digest.get('md5'), 'e2c865db4162bed963bfaa9ef6ac18f0')
        self.assertEqual(digest.get('sha256'), '40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880')

    def test_multi_hash_async(self):
        data = bytes(range(256))
        m = fcs.MultiHash('md5', 'sha256', wantasync=True)
        m.update(data)
        digest = m.digest()
        self.assertEqual(digest.get('md5'), b'\xe2\xc8\x65\xdb\x41\x62\xbe\xd9\x63\xbf\xaa\x9e\xf6\xac\x18\xf0')
        self.assertEqual(digest.get('sha256'), b'\x40\xaf\xf2\xe9\xd2\xd8\x92\x2e\x47\xaf\xd4\x64\x8e\x69\x67\x49\x71\x58\x78\x5f\xbd\x1d\xa8\x70\xe7\x11\x02\x66\xbf\x94\x48\x80')
        digest = m.hexdigest()
        self.assertEqual(digest.get('md5'), 'e2c865db4162bed963bfaa9ef6ac18f0')
        self.assertEqual(digest.get('sha256'), '40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880')

### io_helper

class SafeWriterTestCase(unittest.TestCase):
    def test_write(self):
        data = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        path = tempfile.mktemp(suffix='.txt', prefix='fcs_test_')
        try:
            with fcs.SafeWriter(path) as f:
                f.write(data)
                f.commit()
            with io.open(path, 'r') as f:
                self.assertEqual(f.read(), data)
        finally:
            try:
                os.unlink(path)
            except:
                pass

    def test_write_no_commit(self):
        data = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        path = tempfile.mktemp(suffix='.txt', prefix='fcs_test_')
        try:
            with io.open(path, 'wb') as f:
                f.write(data)
            with self.assertRaises(Exception):
                with fcs.SafeWriter(path) as f:
                    f.write('QWERTYUIOPASDFGHJKLXCVBNMqwertyuiopasdfghjklxcvbnm1234567890')
            with io.open(path, 'rb') as f:
                self.assertEqual(f.read(), data)
        finally:
            try:
                os.unlink(path)
            except:
                pass

### ltsv

class LTSVClassTestCase(unittest.TestCase):
    def test_escape(self):
        self.assertEqual(fcs.LTSV.escape('value'), 'value')
        self.assertEqual(fcs.LTSV.escape('value\twith\ttabs'), 'value\\twith\\ttabs')
        self.assertEqual(fcs.LTSV.escape('value with\n newlines\n'), 'value with\\n newlines\\n')
        self.assertEqual(fcs.LTSV.escape('value \\with \\backslashes'), 'value \\\\with \\\\backslashes')
        self.assertEqual(fcs.LTSV.escape('value \\with\tspecial\n chars'), 'value \\\\with\\tspecial\\n chars')
        self.assertEqual(fcs.LTSV.escape('not \\tab nor \\newline'), 'not \\\\tab nor \\\\newline')

    def test_unescape(self):
        self.assertEqual(fcs.LTSV.unescape('value'), 'value')
        self.assertEqual(fcs.LTSV.unescape('value\\twith\\ttabs'), 'value\twith\ttabs')
        self.assertEqual(fcs.LTSV.unescape('value with\\n newlines\\n'), 'value with\n newlines\n')
        self.assertEqual(fcs.LTSV.unescape('value \\\\with \\\\backslashes'), 'value \\with \\backslashes')
        self.assertEqual(fcs.LTSV.unescape('value \\\\with\\tspecial\\n chars'), 'value \\with\tspecial\n chars')
        self.assertEqual(fcs.LTSV.unescape('\\\\\\tab and \\\\\\newline'), '\\\tab and \\\newline')
        self.assertEqual(fcs.LTSV.unescape('not \\\\tab nor \\\\newline'), 'not \\tab nor \\newline')

    def test_each(self):
        self.assertEqual(list(fcs.LTSV.each('k1:v1\tk2:v2\tk3:\\tv3')), [('k1', 'v1'), ('k2', 'v2'), ('k3', '\tv3')])

    def test_parse(self):
        self.assertEqual(fcs.LTSV.parse('k1:v1\tk2:v2\tk3:\\tv3'), {'k1':'v1', 'k2':'v2', 'k3':'\tv3'})

    def test_generate(self):
        self.assertEqual(fcs.LTSV.generate([('k1', 'v1'), ('k2', 'v2'), ('k3', '\tv3')]), 'k1:v1\tk2:v2\tk3:\\tv3')
        self.assertEqual(fcs.LTSV.generate({'k1': 'v1', 'k2':'v2', 'k3':'\tv3'}), 'k1:v1\tk2:v2\tk3:\\tv3')


class KeyValueTestMock(fcs.KeyValue):
    KEY_ORDER = ['k1', 'nk3']

    @classmethod
    def is_array(cls, key):
        return key == 'arr' or super().is_array(key)

class KeyValueClassTestCase(unittest.TestCase):
    def test_from_ltsv(self):
        x = KeyValueTestMock.from_ltsv('k1:v1\tarr:e1\tk2:v2\tarr:e2')
        self.assertEqual(x.get('k1'), 'v1')
        self.assertEqual(x.get('k2'), 'v2')
        self.assertEqual(x.get('arr'), ['e1', 'e2'])

    def test_to_ltsv(self):
        x = KeyValueTestMock({'k1':'v1', 'k2':'v2'})
        x.add('arr', 'e1')
        x.add('arr', 'e2')
        self.assertEqual(x.to_ltsv(), 'k1:v1\tarr:e1\tarr:e2\tk2:v2')

    def test_invalid_key(self):
        self.assertRaises(KeyError, fcs.KeyValue, {"hash:md5": "0123456789abcdef0123456789abcdef"})
        with self.assertRaises(KeyError):
            kv = fcs.KeyValue({})
            kv.add("hash:md5", "0123456789abcdef0123456789abcdef")

### pathutil

class PathUtilTestCase(unittest.TestCase):
    def test_glob_to_pattern(self):
        self.assertEqual(fcs.PathUtil.glob_to_pattern('part'), '/part$')

        self.assertEqual(fcs.PathUtil.glob_to_pattern('part*'), '/part[^/]*$')
        self.assertEqual(fcs.PathUtil.glob_to_pattern('*part*'), '/[^/]*part[^/]*$')

        self.assertEqual(fcs.PathUtil.glob_to_pattern('/part'), '^/part$')
        self.assertEqual(fcs.PathUtil.glob_to_pattern('/part*'), '^/part[^/]*$')
        self.assertEqual(fcs.PathUtil.glob_to_pattern('/*part*'), '^/[^/]*part[^/]*$')

        self.assertEqual(fcs.PathUtil.glob_to_pattern('/part/'), '^/part/')
        self.assertEqual(fcs.PathUtil.glob_to_pattern('/part*/'), '^/part[^/]*/')
        self.assertEqual(fcs.PathUtil.glob_to_pattern('/*part*/'), '^/[^/]*part[^/]*/')

    def test_match(self):
        self.assertEqual(fcs.PathUtil.match('part', 'xyz/part'), True)
        self.assertEqual(fcs.PathUtil.match('part', 'xyz/part/'), False)
        self.assertEqual(fcs.PathUtil.match('part', 'xyz/part.ext'), False)

        self.assertEqual(fcs.PathUtil.match('part*', 'xyz/part'), True)
        self.assertEqual(fcs.PathUtil.match('part*', 'xyz/part/'), False)
        self.assertEqual(fcs.PathUtil.match('part*', 'xyz/part.ext'), True)

        self.assertEqual(fcs.PathUtil.match('*part', 'xyz/part'), True)
        self.assertEqual(fcs.PathUtil.match('*part', 'xyz/prepart'), True)

        self.assertEqual(fcs.PathUtil.match('pa*rt', 'xyz/part'), True)
        self.assertEqual(fcs.PathUtil.match('pa*rt', 'xyz/pamidrt'), True)
        self.assertEqual(fcs.PathUtil.match('pa*rt', 'pa/rt'), False)

class FileListerTestCase(unittest.TestCase):
    # TODO: test FileLister (how?)
    pass

### filechecksums.config

class FCSConfigArgsStub():
    def __init__(self):
        self.includes = None
        self.excludes = None
        self.algs = None

class FCSConfigTestCase(unittest.TestCase):
    def test_is_array(self):
        self.assertTrue(fcs.FCSConfig.is_array('include'))
        self.assertTrue(fcs.FCSConfig.is_array('exclude'))
        self.assertTrue(fcs.FCSConfig.is_array('alg'))

    def test_from_args_with_no_key(self):
        args = FCSConfigArgsStub()
        config = fcs.FCSConfig.from_args(args)
        self.assertEqual(config.includes(), None)
        self.assertEqual(config.excludes(), None)
        self.assertEqual(config.algs(), None)

    def test_from_args_with_all_keys(self):
        args = FCSConfigArgsStub()
        args.includes = ['/src/']
        args.excludes = ['.svn/', '.git/']
        args.algs = ['md5', 'sha256']
        config = fcs.FCSConfig.from_args(args)
        self.assertEqual(config.includes(), ['/src/'])
        self.assertEqual(config.excludes(), ['.svn/', '.git/'])
        self.assertEqual(config.algs(), ['md5', 'sha256'])

    def test_from_ltsv(self):
        config = fcs.FCSConfig.from_ltsv("alg:md5\talg:sha256\tinclude:/src/\texclude:.svn/\texclude:.git/")
        self.assertEqual(config.includes(), ['/src/'])
        self.assertEqual(config.excludes(), ['.svn/', '.git/'])
        self.assertEqual(config.algs(), ['md5', 'sha256'])

    def test_is_exclude_dir(self):
        config = fcs.FCSConfig.from_ltsv("include:aaa/\texclude:bbb/")
        config.prepare_patterns()
        self.assertFalse(config.is_exclude_dir('aaa/'))
        self.assertFalse(config.is_exclude_dir('bbb'))
        self.assertTrue(config.is_exclude_dir('bbb/'))
        self.assertTrue(config.is_exclude_dir('aaa/bbb/'))
        config = fcs.FCSConfig.from_ltsv("include:aaa/\tinclude:bbb/")
        config.global_excludes = False
        config.prepare_patterns()
        self.assertFalse(config.is_exclude_dir('aaa/'))
        self.assertFalse(config.is_exclude_dir('bbb'))
        self.assertFalse(config.is_exclude_dir('bbb/'))
        self.assertFalse(config.is_exclude_dir('aaa/bbb/'))

    def test_should_exclude(self):
        config = fcs.FCSConfig.from_ltsv("include:aaa/\tinclude:xxx\texclude:bbb/\texclude:yyy")
        config.prepare_patterns()
        self.assertFalse(config.should_exclude('aaa/'))
        self.assertFalse(config.should_exclude('xxx'))
        self.assertTrue(config.should_exclude('bbb/'))
        self.assertTrue(config.should_exclude('bbb/xxx'))
        self.assertTrue(config.should_exclude('aaa/bbb/'))
        self.assertTrue(config.should_exclude('yyy'))
        self.assertTrue(config.should_exclude('aaa/yyy'))
        config = fcs.FCSConfig.from_ltsv("include:aaa/\tinclude:xxx")
        config.global_excludes = False
        config.prepare_patterns()
        self.assertFalse(config.should_exclude('aaa/'))
        self.assertFalse(config.should_exclude('xxx'))
        self.assertFalse(config.should_exclude('bbb/'))
        self.assertFalse(config.should_exclude('yyy'))

    def test_should_include(self):
        config = fcs.FCSConfig.from_ltsv("include:aaa/\tinclude:xxx\texclude:bbb/\texclude:yyy")
        config.prepare_patterns()
        self.assertTrue(config.should_include('aaa/'))
        self.assertTrue(config.should_include('aaa/yyy'))
        self.assertTrue(config.should_include('bbb/aaa/'))
        self.assertTrue(config.should_include('xxx'))
        self.assertTrue(config.should_include('bbb/xxx'))
        self.assertFalse(config.should_include('bbb/'))
        self.assertFalse(config.should_include('yyy'))
        config = fcs.FCSConfig.from_ltsv("exclude:aaa/\texclude:xxx")
        config.global_excludes = False
        config.prepare_patterns()
        self.assertTrue(config.should_include('aaa/'))
        self.assertTrue(config.should_include('xxx'))
        self.assertTrue(config.should_include('bbb/'))
        self.assertTrue(config.should_include('yyy'))

class FCSFilesTestCase(unittest.TestCase):
    # TODO: test FCSFiles (how?)
    pass

### filechecksums.store

class FCSHeaderTestCase(unittest.TestCase):
    def test(self):
        header = fcs.FCSHeader({'magic': 'test', 'alg': ['md5', 'sha256']})
        self.assertEqual(header.get('magic'), 'FCSSTORE')
        self.assertEqual(header.to_ltsv(), 'magic:FCSSTORE\talg:md5\talg:sha256')

class FCSEntryTestCase(unittest.TestCase):
    def test_init(self):
        entry = fcs.FCSEntry({'path': 'aaa/xxx', 'size': 4096, 'mtime': 1676818800})
        self.assertEqual(entry.path, 'aaa/xxx')
        self.assertEqual(entry.size, 4096)
        self.assertEqual(entry.mtime, 1676818800)

    def test_from_ltsv(self):
        entry = fcs.FCSEntry.from_ltsv('path:aaa/xxx\tsize:4096\tmtime:1676818800')
        self.assertEqual(entry.path, 'aaa/xxx')
        self.assertEqual(entry.size, 4096)
        self.assertEqual(entry.mtime, 1676818800)

    def test_from_path(self):
        entry = fcs.FCSEntry.from_path('aaa/xxx')
        self.assertEqual(entry.path, 'aaa/xxx')
        self.assertEqual(entry.size, -1)
        self.assertEqual(entry.mtime, 0)

class FileCheckSumsClassTestCase(unittest.TestCase):
    def test_is_fcsstore(self):
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\n')
            tmp.flush()
            self.assertTrue(fcs.FileCheckSums.is_fcsstore(tmp.name))
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\talg:md5\tinclude:/src/')
            tmp.flush()
            self.assertTrue(fcs.FileCheckSums.is_fcsstore(tmp.name))

    def test_not_is_fcsstore(self):
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\n')
            tmp.close()
            self.assertFalse(fcs.FileCheckSums.is_fcsstore(tmp.name))
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\n')
            tmp.flush()
            os.chmod(tmp.name, 0o200)
            self.assertFalse(fcs.FileCheckSums.is_fcsstore(tmp.name))

    def test_load(self):
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\talg:md5\n')
            tmp.write(b'md5:d41d8cd98f00b204e9800998ecf8427e\tsize:4096\tmtime:1676818800\tpath:aaa/xxx\n')
            tmp.flush()
            store = fcs.FileCheckSums.load(tmp.name)
            self.assertEqual(store.config.algs(), ['md5'])
            self.assertEqual(len(store.files), 1)

    def test_load_config(self):
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\talg:md5\n')
            tmp.write(b'md5:d41d8cd98f00b204e9800998ecf8427e\tsize:4096\tmtime:1676818800\tpath:aaa/xxx\n')
            tmp.flush()
            store = fcs.FileCheckSums.load_config(tmp.name)
            self.assertEqual(store.config.algs(), ['md5'])
            self.assertEqual(len(store.files), 0)

    def test_non_writable_file(self):
        with tempfile.NamedTemporaryFile(suffix='.fcsstore', prefix='fcs_test_') as tmp:
            tmp.write(b'magic:FCSSTORE\talg:md5\n')
            tmp.flush()
            os.chmod(tmp.name, 0o400)
            with self.assertRaises(ValueError):
                store = fcs.FileCheckSums.load(tmp.name, readonly=False)
            with self.assertRaises(ValueError):
                store = fcs.FileCheckSums.load_config(tmp.name, readonly=False)

    def test_non_writable_dir(self):
        with tempfile.TemporaryDirectory(prefix='fcs_test_') as tmp:
            path = tmp+"/.fcsstore"
            with io.open(path, 'wb') as f:
                f.write(b'magic:FCSSTORE\talg:md5\n')
            os.chmod(tmp, 0o500)
            with self.assertRaises(ValueError):
                store = fcs.FileCheckSums.load(path, readonly=False)
            with self.assertRaises(ValueError):
                store = fcs.FileCheckSums.load_config(path, readonly=False)

    def test_save(self):
        pass

    def test_save_config(self):
        pass

    def test_add_get_remove(self):
        store = fcs.FileCheckSums('test.fcsstore')
        store.add(fcs.FCSEntry({'path': 'aaa/yyy'}))
        store.add(fcs.FCSEntry({'path': 'aaa/xxx3'}))
        store.add(fcs.FCSEntry({'path': 'aaa/xxx1'}))
        store.add(fcs.FCSEntry({'path': 'aaa/xxx2'}))
        self.assertEqual(len(store.files), 4)
        store.remove(store.files[3])
        self.assertEqual(len(store.files), 3)
        self.assertEqual(store.get('aaa/xxx1'), store.files[0])
        self.assertEqual(store.get('aaa/xxx2'), store.files[1])
        self.assertEqual(store.get('aaa/xxx3'), store.files[2])
        pass

if __name__ == '__main__':
    unittest.main()
