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

def test_get_entry():
    """
    Try to get entries.
    """
    db = keepass.kpdb.Database()
    db.add_entry(path='Secrets/Terrible', title='Gonk', username='foo', password='bar', url='https://example.org/')
    db.add_entry(path='Secrets/Terrible2', title='Gonk2', username='foo2', password='bar2', url='https://example.org/2')
    db.add_entry(path='Secrets/Terrible3', title='Gonk3', username='foo3', password='bar3', url='https://example.org/3')

    entry = db.get_entry('Gonk4')
    assert entry == None

    entry = db.get_entry('Gonk2')
    assert entry.password == 'bar2'

    entry = db.get_entry('foo3')
    assert entry.password == 'bar3'