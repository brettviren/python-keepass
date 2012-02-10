# -*- coding: utf-8 -*-
'''
Classes to construct a hiearchy holding infoblocks.
'''

from .decorators import notimplemented

def path2list(path):
    '''
    Convert a '/' separated string into a list.
    '''
    if isinstance(path, str):
        # remove trailing '/'
        if path.endswith('/'):
            path = path[:-1]
        return path.split('/')
    return list(path)


class Visitor(object):
    '''
    A class that can visit group/entry hierarchy via hier.visit(). 

    A visitor should be a callable with the signature
        
        visitor(obj) -> (value, bail)
        
    The obj is either the node's group or one of it's entries or None.
    The return values control the descent
        
    If value is ever non-None it is assumed the descent is over
    and this value is returned.

    If bail is ever True, the current node is abandoned in the
    descent.  This can be used to avoid sub trees that are not
    interesting to the visitor.
    '''
    @notimplemented
    def __call__(self):
        pass


class Walker(object):
    '''
    A class that can visit the node hierarchy

    Like a visitor, this callable should return a tuple of
    (value,bail). non-None to abort the descent and return that value.
    If bail is True, then drop the current node and move to its next
    sister.
    '''
    @notimplemented
    def __call__(self,node):
        pass


class NodeDumper(Walker):

    def __call__(self,node):
        if not node.group:
            print 'Top'
            return (None, None)
        print '  '*node.level*2,node.group.name(),node.group.groupid,\
            len(node.entries),len(node.nodes)
        return (None, None)


class FindGroupNode(Walker):
    '''Return the node holding the group of the given name.  If name
    has any slashes it will be interpreted as a path ending in that
    group'''
    def __init__(self,path):
        self._collected = []
        self.best_match = None
        self.path = path2list(path)
        print 'Finding path',path

    def __call__(self,node):
        if not self.path: 
            print 'Bailing, no path'
            return (None,True)
        if not node.group:
            if self.path[0] == "" or self.path[0] == "None" or self.path[0] is None:
                self.path.pop(0)
            print 'Skipping node with null group.'
            return (None,None)

        top_name = self.path[0]
        obj_name = node.group.name()

        groupid = node.group.groupid
        print self.path,obj_name,groupid

        if top_name != obj_name:
            print top_name,'!=',obj_name
            return (None,True) # bail on the current node

        self.best_match = node

        if len(self.path) == 1: # we have a full match
            if self.stop_on_first:
                return node,True # got it!
            else:                # might have a matching sister
                self._collected.append(node)
                return (None,None)

        self.path.pop(0)
        return (None,None)  # keep going


class CollectVisitor(Visitor):
    '''
    A callable visitor that will collect the groups and entries into
    flat lists.  After the descent the results are available in the
    .groups and .entries data memebers.
    '''
    def __init__(self):
        self.groups = []
        self.entries = []

    def __call__(self, g_or_e):
        if g_or_e is None:
            return (None,None)
        from infoblock import GroupInfo
        if isinstance(g_or_e, GroupInfo):
            self.groups.append(g_or_e)
        else:
            self.entries.append(g_or_e)
        return (None,None)


class PathVisitor(Visitor):
    '''
    A callable visitor to descend via hier.visit() method and
    return the group or the entry matching a given path.

    The path is a list of group names with the last element being
    either a group name or an entry title.  The path can be a list
    object or a string interpreted to be delimited by slashs (think
    UNIX pathspec).

    If stop_on_first is False, the visitor will not abort after the
    first match but will instead keep collecting all matches.  This
    can be used to collect groups or entries that are degenerate in
    their group_name or title, respectively.  After the descent the
    collected values can be retrived from PathVisitor.results()

    This visitor also maintains a best match.  In the event of failure
    (return of None) the .best_match data member will hold the group
    object that was located where the path diverged from what was
    found.  The .path data memeber will retain the remain part of the
    unmatched path.
    '''
    def __init__(self,path,stop_on_first = True):
        self._collected = []
        self.best_match = None
        self.stop_on_first = stop_on_first
        self.path = path2list(path)

    def results(self): 
        'Return a list of the matched groups or entries'
        return self._collected

    def __call__(self,g_or_e):
        if not self.path: return (None,None)

        top_name = self.path[0] or "None"
        obj_name = "None"
        if g_or_e: obj_name = g_or_e.name()

        from infoblock import GroupInfo

        if top_name != obj_name:
            if isinstance(g_or_e,GroupInfo):
                return (None,True) # bail on the current node
            else:
                return (None,None) # keep going

        self.best_match = g_or_e

        if len(self.path) == 1: # we have a full match
            if self.stop_on_first:
                return g_or_e,True # got it!
            else:                  # might have a matching sister
                self._collected.append(g_or_e)
                return (None,None)

        self.path.pop(0)
        return (None,None)  # keep going


class Node(object):
    '''
    A node in the group hiearchy.

    This basically associates entries to their group

    Holds:

     * zero or one group - zero implies top of hierarchy
     * zero or more nodes
     * zero or more entries
    '''

    def __init__(self,group=None,entries=None,nodes=None):
        self.group = group
        if nodes is None:
            nodes = []
        self.nodes = nodes
        if entries is None:
            entries = []
        self.entries = entries

    def level(self):
        'Return the level of the group or -1 if have no group'
        if self.group:
            return self.group.level
        return -1

    def __str__(self):
        return self.pretty()

    def name(self):
        'Return name of group or None if no group'
        if self.group:
            return self.group.group_name

    def pretty(self,depth=0):
        'Pretty print this Node and its contents'
        tab = '  '*depth
        me = "%s%s (%d entries) (%d subnodes)\n"%\
            (tab,self.name(),len(self.entries),len(self.nodes))
        children = []
        for e in self.entries:
            s = "%s%s%s: %s\n"%(tab,tab,e.title,e.username)
            children.append(s)
        for n in self.nodes:
            children.append(n.pretty(depth+1))
        return me + ''.join(children)

    def node_with_group(self,group):
        'Return the child node holding the given group'
        if self.group == group:
            return self
        for child in self.nodes:
            ret = child.node_with_group(group)
            if ret:
                return ret


def visit(node,visitor):
    '''
    Depth-first descent into the group/entry hierarchy.
    
    The order of visiting objects is: this node's group,
    recursively calling this function on any child nodes followed
    by this node's entries.
    
    See docstring for hier.Visitor for information on the given visitor. 
    '''
    val,bail = visitor(node.group)
    if val is not None or bail: return val
    
    for n in node.nodes:
        val = visit(n,visitor)
        if val is not None:
            return val
    
    for e in node.entries:
        val,bail = visitor(e)
        if val is not None or bail:
            return val


def walk(node,walker):
    '''
    Depth-first descent into the node hierarchy.
    
    See docstring for hier.Walker for information on the given visitor. 
    '''
    value,bail = walker(node)
    if value is not None or bail:
        return value

    for sn in node.nodes:
        value = walk(sn,walker)
        if value is not None:
            return value
