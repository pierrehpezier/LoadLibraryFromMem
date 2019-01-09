#!/usr/bin/env python
import urllib2
import sys
from bs4 import BeautifulSoup
'''
ugly script to help creating proto from msdn page.
needs human check
'''
response = urllib2.urlopen(sys.argv[1])
html = response.read()

soup = BeautifulSoup(html, "html.parser")
try:
    prototype = soup.find('code').text.strip()
except AttributeError:
    prototype = soup.findAll('pre')[0].text.strip()
if len(prototype.split('\n')) <= 2:
    prototype = soup.findAll('pre')[0].text.strip()
    #prototype = soup.find(attrs={'class': 'x-hidden-focus'}).text.strip()
prototype = prototype.replace('WINAPI ', '')
#python a.py https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
dll = ''
for lib in soup.findAll('td'):
    if '.dll' in lib.text:
        dll = lib.text.lower().split()[0]
        break
dll = dll.encode('utf-8')

funcdef =  prototype.split('\n')[0].rstrip('(').strip().split()
if len(funcdef) == 3:
    funcdef = funcdef[1:]


proto, funcname = funcdef
funcname = funcname.strip('(')
paramlist = []
for item in prototype.split('\n')[1:-1]:
    param = item.split()
    if len(param) == 3:
        param = param[1:]
    paramlist.append(param)

if funcname + 'A' in html.decode('utf-8'):
    funcname += 'A'

args = ''
argproto = ''
argval = ''
for param in paramlist:
    if len(args) > 0:
        args += ', '
        argproto += ', '
        argval += ', '
    if param[1][0] == '*':
        param[1] = param[1][1:]
        param[0] = param[0].strip(',') + '*'
    args += param[0] + ' ' + param[1].strip(',')
    argproto += param[0]
    argval += param[1].strip(',')

retval = '''
{2} My{0}({1})
'''.format(funcname, args, proto) + '{'

retval += '''
    char {0}_strz[] = "{0}";
'''.format(funcname)

retval += '''    char {}_strz[] = "{}";
'''.format(dll.replace('.', '_'), dll)

retval += '''    void *_My{0} = MyGetProcAddress(MyLoadLibrary({1}_strz), {0}_strz);
'''.format(funcname, dll.replace('.', '_'), )

retval += '''    return (*({0}(*)({1}))_My{3})({2});
'''.format(proto, argproto, argval, funcname)
retval += '}'
#.format(
#funcname
#)
print retval
