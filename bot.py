#!/usr/bin/env python
"""
bot.py - jenni IRC Bot
Copyright 2009-2013, yano (yanovich.net)
Copyright 2008-2013, Sean B. Palmer (inamidst.com)
Licensed under the Eiffel Forum License 2.

More info:
 * jenni: https://github.com/myano/jenni/
 * Phenny: http://inamidst.com/phenny/
"""

import time, sys, os, re, threading, imp
import irc

home = os.getcwd()

def decode(bytes):
    try: text = bytes.decode('utf-8')
    except UnicodeDecodeError:
        try: text = bytes.decode('iso-8859-1')
        except UnicodeDecodeError:
            text = bytes.decode('cp1252')
    return text

class Jenni(irc.Bot):
    def __init__(self, config):
        lc_pm = None
        if hasattr(config, "logchan_pm"): lc_pm = config.logchan_pm
        logging = False
        if hasattr(config, "logging"): logging = config.logging
        ipv6 = False
        if hasattr(config, 'ipv6'): ipv6 = config.ipv6
        serverpass = None
        if hasattr(config, 'serverpass'): serverpass = config.serverpass
        user = None
        if hasattr(config, 'user'): user = config.user
        args = (config.nick, config.name, config.channels, user, serverpass, lc_pm, logging, ipv6)
        ## next, try putting a try/except around the following line
        irc.Bot.__init__(self, *args)
        self.config = config
        self.doc = {}
        self.stats = {}
        self.times = {}
        self.excludes = {}
        if hasattr(config, 'excludes'):
            self.excludes = config.excludes
        self.setup()

    def setup(self):
        self.variables = {}

        filenames = []

        # Default module folder + extra folders
        module_folders = [os.path.join(home, 'modules')]
        module_folders.extend(getattr(self.config, 'extra', []))

        excluded = getattr(self.config, 'exclude', [])
        enabled = getattr(self.config, 'enable', [])

        for folder in module_folders:
            if os.path.isfile(folder):
                filenames.append(folder)
            elif os.path.isdir(folder):
                for fn in os.listdir(folder):
                    if fn.endswith('.py') and not fn.startswith('_'):
                        name = os.path.basename(fn)[:-3]
                        # If whitelist is present only include whitelisted
                        # Never include blacklisted items
                        if name in enabled or not enabled and name not in excluded:
                            filenames.append(os.path.join(folder, fn))

        modules = []
        for filename in filenames:
            name = os.path.basename(filename)[:-3]
            # if name in sys.modules:
            #     del sys.modules[name]
            try: module = imp.load_source(name, filename)
            except Exception, e:
                print >> sys.stderr, "Error loading %s: %s (in bot.py)" % (name, e)
            else:
                if hasattr(module, 'setup'):
                    module.setup(self)
                self.register(vars(module))
                modules.append(name)

        if modules:
            print >> sys.stderr, 'Registered modules:', ', '.join(sorted(modules))
        else:
            print >> sys.stderr, "Warning: Couldn't find any modules"

        self.bind_commands()

    def register(self, variables):
        # This is used by reload.py, hence it being methodised
        for name, obj in variables.iteritems():
            if hasattr(obj, 'commands') or hasattr(obj, 'rule'):
                self.variables[name] = obj

    def bind_commands(self):
        self.commands = {'high': {}, 'medium': {}, 'low': {}}

        def bind(self, priority, regexp, func):
            # register documentation
            if not hasattr(func, 'name'):
                func.name = func.__name__
            if func.__doc__:
                if hasattr(func, 'example'):
                    example = func.example
                    example = example.replace('$nickname', self.nick)
                else: example = None
                self.doc[func.name] = (func.__doc__, example)
            self.commands[priority].setdefault(regexp, []).append(func)
            regexp = re.sub('\x01|\x02', '', regexp.pattern)
            return (func.__module__, func.__name__, regexp, priority)

        def sub(pattern, self=self):
            # These replacements have significant order
            pattern = pattern.replace('$nickname', re.escape(self.nick))
            return pattern.replace('$nick', r'%s[,:] +' % re.escape(self.nick))

        bound_funcs = []
        for name, func in self.variables.iteritems():
            # print name, func
            if not hasattr(func, 'priority'):
                func.priority = 'medium'

            if not hasattr(func, 'thread'):
                func.thread = True

            if not hasattr(func, 'event'):
                func.event = 'PRIVMSG'
            else:
                if func.event:
                    func.event = func.event.upper()
                else:
                    continue

            if not hasattr(func, 'rate'):
                if hasattr(func, 'commands'):
                    func.rate = 3
                else:
                    func.rate = -1

            if hasattr(func, 'rule'):
                if isinstance(func.rule, str):
                    pattern = sub(func.rule)
                    regexp = re.compile(pattern)
                    bound_funcs.append(bind(self, func.priority, regexp, func))

                if isinstance(func.rule, tuple):
                    # 1) e.g. ('$nick', '(.*)')
                    if len(func.rule) == 2 and isinstance(func.rule[0], str):
                        prefix, pattern = func.rule
                        prefix = sub(prefix)
                        regexp = re.compile(prefix + pattern)
                        bound_funcs.append(bind(self, func.priority, regexp, func))

                    # 2) e.g. (['p', 'q'], '(.*)')
                    elif len(func.rule) == 2 and isinstance(func.rule[0], list):
                        prefix = self.config.prefix
                        commands, pattern = func.rule
                        for command in commands:
                            command = r'(?i)(%s)\b(?: +(?:%s))?' % (command, pattern)
                            regexp = re.compile(prefix + command)
                            bound_funcs.append(bind(self, func.priority, regexp, func))

                    # 3) e.g. ('$nick', ['p', 'q'], '(.*)')
                    elif len(func.rule) == 3:
                        prefix, commands, pattern = func.rule
                        prefix = sub(prefix)
                        for command in commands:
                            command = r'(?i)(%s) +' % command
                            regexp = re.compile(prefix + command + pattern)
                            bound_funcs.append(bind(self, func.priority, regexp, func))

            if hasattr(func, 'commands'):
                for command in func.commands:
                    template = r'(?i)^%s(%s)(?: +(.*))?$'
                    pattern = template % (self.config.prefix, command)
                    regexp = re.compile(pattern)
                    bound_funcs.append(bind(self, func.priority, regexp, func))

        max_pattern_width = max(len(f[2]) for f in bound_funcs)
        for module, name, regexp, priority in sorted(bound_funcs):
            encoded_regex = regexp.encode('utf-8').ljust(max_pattern_width)
            print ('{0} | {1}.{2}, {3} priority'.format(encoded_regex,  module, name, priority))

    def wrapped(self, origin, text, match):
        class JenniWrapper(object):
            def __init__(self, jenni):
                self._bot = jenni

            def __getattr__(self, attr):
                sender = origin.sender or text
                if attr == 'reply':
                    return (lambda msg:
                        self._bot.msg(sender, origin.nick + ': ' + msg))
                elif attr == 'say':
                    return lambda msg: self._bot.msg(sender, msg)
                elif attr == 'bot':
                    # Allow deprecated usage of jenni.bot.foo but print a warning to the console
                    print "Warning: Direct access to jenni.bot.foo is deprecated.  Please use jenni.foo instead."
                    import traceback
                    traceback.print_stack()
                    # Let this keep working by passing it transparently to _bot
                    return self._bot
                return getattr(self._bot, attr)

            def __setattr__(self, attr, value):
                if attr in ('_bot',):
                    # Explicitly allow the wrapped class to be set during __init__()
                    return super(JenniWrapper, self).__setattr__(attr, value)
                else:
                    # All other attributes will be set on the wrapped class transparently
                    return setattr(self._bot, attr, value)

        return JenniWrapper(self)

    def input(self, origin, text, bytes, match, event, args):
        class CommandInput(unicode):
            def __new__(cls, text, origin, bytes, match, event, args):
                s = unicode.__new__(cls, text)
                s.sender = origin.sender
                s.nick = origin.nick
                s.event = event
                s.bytes = bytes
                s.match = match
                s.group = match.group
                s.groups = match.groups
                s.ident = origin.user
                s.raw = origin
                s.args = args
                s.mode = origin.mode
                s.mode_target = origin.mode_target
                s.names = origin.names
                s.full_ident = origin.full_ident
                s.admin = origin.nick in self.config.admins
                if s.admin == False:
                    for each_admin in self.config.admins:
                        re_admin = re.compile(each_admin)
                        if re_admin.findall(origin.host):
                            s.admin = True
                        elif '@' in each_admin:
                            temp = each_admin.split('@')
                            re_host = re.compile(temp[1])
                            if re_host.findall(origin.host):
                                s.admin = True
                s.owner = origin.nick + '@' + origin.host == self.config.owner
                if s.owner == False: s.owner = origin.nick == self.config.owner
                s.host = origin.host
                return s

        return CommandInput(text, origin, bytes, match, event, args)

    def call(self, func, origin, jenni, input):
    nick = input.nick.lower()
    
    # Rate limiting check
    if not self.is_rate_limited(nick, func, input):
        return
    
    # Exclusion checks
    if self.is_excluded(input.sender.lower(), func):
        return
    
    # Execute the function and handle any errors
    self.execute_function(func, jenni, input)

    def is_rate_limited(self, nick, func, input):
        if nick in self.times:
            if func in self.times[nick]:
                if not input.admin:  # admins are not rate limited
                    if time.time() - self.times[nick][func] < func.rate:
                        self.times[nick][func] = time.time()
                        return False
        else:
            self.times[nick] = dict()
        
        self.times[nick][func] = time.time()
        return True

    def is_excluded(self, sender, func):
        try:
            if hasattr(self, 'excludes'):
                if sender in self.excludes:
                    exclusions = self.excludes[sender]
                    if '!' in exclusions:
                        return True  # block all function calls for this channel
                    fname = func.func_code.co_filename.split('/')[-1].split('.')[0]
                    if fname in exclusions:
                        return True  # block function call if channel is blacklisted
        except Exception as e:
            print(f"Error attempting to block: {func.name}, Error: {str(e)}")
            self.error(origin)
        return False

    def execute_function(self, func, jenni, input):
        try:
            func(jenni, input)
        except Exception as e:
            self.error(origin)

    def limit(self, origin, func):
        if origin.sender and origin.sender.startswith('#'):
            if hasattr(self.config, 'limit'):
                limits = self.config.limit.get(origin.sender)
                if limits and (func.__module__ not in limits):
                    return True
        return False


    def dispatch(self, origin, args):
    bytes, event, args = args[0], args[1], args[2:]
    text = decode(bytes)

    for priority in ('high', 'medium', 'low'):
        items = self.commands[priority].items()
        for regexp, funcs in items:
            for func in funcs:
                if event != func.event: continue

                if regexp.match(text):
                    if self.limit(origin, func): continue

                    if self.is_blocked(origin, func):
                        return

                    self.execute_command(func, origin, text, bytes, match, event, args)

    def is_blocked(self, origin, func):
        blocked = self.load_blocked_items()
        if any(self.check_block(item, getattr(origin, attr)) for attr, item in blocked.items()):
            return True
        return False

    def load_blocked_items(self):
        with open("blocks", "r") as g:
            contents = g.readlines()
        return {
            "masks": [line.strip() for line in contents[0].split(',') if line.strip()],
            "nicks": [line.strip() for line in contents[1].split(',') if line.strip()],
            "idents": [line.strip() for line in contents[2].split(',') if line.strip()]
        }

    def check_block(self, block_items, origin_attribute):
        for item in block_items:
            try:
                if re.compile(item).findall(origin_attribute):
                    return True
            except re.error:
                if item in origin_attribute:
                    return True
        return False

    def execute_command(self, func, origin, text, bytes, match, event, args):
        jenni = self.wrapped(origin, text, match)
        input = self.input(origin, text, bytes, match, event, args)

        # Run command on a new thread if required by the function
        if func.thread:
            threading.Thread(target=self.call, args=(func, origin, jenni, input)).start()
        else:
            self.call(func, origin, jenni, input)

        self.update_stats(func, origin)

    def update_stats(self, func, origin):
        sources = [origin.sender, origin.nick]
        for source in sources:
            if (func.name, source) in self.stats:
                self.stats[(func.name, source)] += 1
            else:
                self.stats[(func.name, source)] = 1


if __name__ == '__main__':
    print __doc__

