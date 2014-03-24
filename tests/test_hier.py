from keepass import hier

groups = []

class Header():
    def __init__(self):
        self.ngroups = 0

class GroupIDGenerator(object):
    def __init__(self):
        self.groupid = 0
    
    def gen_groupid(self):
        self.groupid += 1
        return self.groupid

def test_hierarchy():
    top = hier.Node()
    hier.mkdir(top, 'SubDir/SubSubDir', GroupIDGenerator().gen_groupid, groups, Header())
    dumper = hier.NodeDumper()
    hier.walk(top,dumper)


# filename = sys.argv[1]
# masterkey  = sys.argv[2]
# db = kpdb.Database(filename,masterkey)
# h = db.hierarchy()
# print h

# path = sys.argv[3]
# # obj = h.get(path)
# # print path,' --> ',obj

# from keepass import hier
# visitor = hier.PathVisitor(path,False)
# obj = hier.walk(h,visitor)
# print 'results for',path
# for res in visitor.results():
#     print res
# print 'best match:',visitor.best_match
# print 'remaining path:',visitor.path

# visitor= hier.CollectVisitor()
# hier.walk(h,visitor)
# print 'Groups:'
# for g in visitor.groups:
#     print '\t',g.name(),g.groupid
# print 'Entries:'
# for e in visitor.entries:
#     print '\t',e.name(),e.groupid
