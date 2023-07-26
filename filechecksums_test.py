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

if __name__ == '__main__':
    unittest.main()
