import tempfile
import shutil
import os

import keepass.kpdb

def test_write():
    """
    Try to create a file and then read it back in.
    """
    password = 'REINDEER FLOTILLA'
    tempdir = tempfile.mkdtemp()
    kdb_path = os.path.join(tempdir, 'test_write.kdb')
    try:
        db = keepass.kpdb.Database()
        db.add_entry(path='Secrets/Terrible', title='Gonk', username='foo', password='bar', url='https://example.org/')
        assert len(db.groups)  == 2
        assert len(db.entries) == 1
        db.write(kdb_path, password)
        assert os.path.isfile(kdb_path)
        
        db2 = keepass.kpdb.Database(kdb_path, password)
        assert len(db.groups)  == 2
        assert len(db.entries) == 1
        assert db.entries[0].name() == 'Gonk'
        
    finally:
        shutil.rmtree(tempdir)
