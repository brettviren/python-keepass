#!/usr/bin/env python
'''
Classes to construct a hiearchy holding infoblocks.
'''

class Visitor(object):
    '''
    A class that can visit a hier.Node hierarchy via Node.walk(). 

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
    def __call_(self):
        notimplemented

    pass

class CollectVisitor(Visitor):
    '''
    A callable visitor that will collect the groups and entries into
    flat lists.  After the descent the results are available in the
    .groups and .entries data memebers.
    '''
    def __init__(self):
        self.groups = []
        self.entries = []
        return

    def __call__(self,g_or_e):
        if g_or_e is None: return (None,None)
        from infoblock import GroupInfo
        if isinstance(g_or_e,GroupInfo):
            self.groups.append(g_or_e)
        else:
            self.entries.append(g_or_e)
        return (None,None)
    pass


class PathVisitor(Visitor):
    '''
    A callable visitor to descend via Node.walk() method and
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
        if isinstance(path,str): 
            path = path.split('/')
            if path[-1] == '': path.pop()
        else: path = list(path) # assure unique own copy
        self.path = path
        return

    def results(self): 
        'Return a list of the matched groups or entries'
        return self._collected

    def __call__(self,g_or_e):
        if not self.path: return (None,None)

        top_name = self.path[0] or "None"
        obj_name = "None"
        if g_or_e: obj_name = g_or_e.name()

        groupid = None
        if g_or_e: groupid = g_or_e.groupid
        #print self.path,obj_name,groupid

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
            pass

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
        self.nodes = nodes or list()
        self.entries = entries or list()
        return

    def level(self):
        'Return the level of the group or -1 if have no group'
        if self.group: return self.group.level
        return -1

    def name(self):
        'Return name of group or None if no group'
        if self.group: return self.group.group_name
        return None

    def pretty(self,depth=0):
        'Pretty print this Node and its contents'
        tab = '  '*depth


        me = "%s%s (%d entries) (%d subnodes)\n"%\
            (tab,self.name(),len(self.entries),len(self.nodes))

        children=[]
        for e in self.entries:
            s = "%s%s(%s: %s)\n"%(tab,tab,e.title,e.username)
            children.append(s)
            continue

        for n in self.nodes:
            children.append(n.pretty(depth+1))
            continue

        return me + ''.join(children)

    def __str__(self):
        return self.pretty()

    def walk(self,visitor):
        '''
        Depth-first descent into the hierarchy.

        The order of visiting objects is: this node's group,
        recursively calling this function on any child nodes followed
        by this node's entries.
        
        See docstring for hier.Visitor for information on the given visitor. 
        '''
        val,bail = visitor(self.group)
        if val is not None or bail: return val

        for n in self.nodes:
            val = n.walk(visitor)
            if val is not None: return val
            continue

        for e in self.entries:
            val,bail = visitor(e)
            if val is not None or bail: return val
            continue

        return None

    def node_with_group(self,group):
        'Return the child node holding the given group'
        if self.group == group:
            return self
        for child in self.nodes:
            ret = child.node_with_group(group)
            if ret: return ret
            continue
        return None

    def get(self,path):
        '''Return the group or the entry found at the given "path".
        The path is a list of group names with the last element being
        either a group name or an entry title.  The path can be a list
        object or a string interpreted to be delimited by slashs
        (think UNIX pathspec).
        '''

        if not path: return None
        if isinstance(path,str): 
            path = path.split('/')
            if path[-1] == '': path.pop()
        else: path = list(path) # assure unique own copy

        #print 'path',path
        mine = path.pop(0)      # name of one of our nodes or entries
        if not mine:            # handle case of being at the top
            mine = None 

        #print '-->Inside:',self.name(),'path is',path

        # Already strayed from the path
        if mine != self.name(): 
            #print mine,'is not me',self.name()
            return None

        # I'm at the end of the line
        if not path: return self.group

        # might be one of my entries
        if len(path) == 1:
            for ent in self.entries:
                #print 'checking entry',ent.title
                if path[0] == ent.title: return ent
                continue
            pass

        # Delegate to child nodes
        for child in self.nodes:
            #print 'checking group',child.name()
            hit = child.get(path)
            if hit: return hit
            continue
        
        # go fish
        return None
    
