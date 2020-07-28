#!/usr/bin/env python3
import cgi
import cgitb
import os
import pprint
import uuid
from http import cookies

# debug
cgitb.enable()

##################################################################

# library
def getenv(x, default=None):
    return os.environ.get(x, default)

def otag(tag):
    print('<{tag}>'.format(tag=tag))

def ctag(tag):
    print('</{tag}>'.format(tag=tag))

def xwrap(tag, x):
    return '<{tag}>{x}</{tag}>'.format(tag=tag, x=cgi.escape(str(x)))

def xprint(x, tag='p'):
    print(xwrap(tag, x))

def kvwrap(tag, k, v):
    return '<{tag}>{k}: <tt>{v}</tt></{tag}>'.format(tag=tag, k=cgi.escape(str(k)), v=cgi.escape(str(v)))

def kvprint(k, v, tag='p'):
    print(kvwrap(tag, k, v))

##################################################################

# env
env_cookie = getenv('HTTP_COOKIE')
env_eotk = getenv('HTTP_X_FROM_ONION')
env_https = getenv('HTTPS') == 'on'
env_port = getenv('SERVER_PORT')
env_scheme = getenv('REQUEST_SCHEME')
env_ua = getenv('HTTP_USER_AGENT')
env_uri = getenv('REQUEST_URI')

# constants/ish
content_type = 'text/html'
cookie_name = 'ONION_COOKIE_LEAKTEST'
max_age = 600
name_dns = 'dropsafe.crypticide.com'
name_onion = 'dropsafe.dropsafezeahmyho.onion'
uri_path = '/leaktest/'

# cookie setting
setval = '{0}:{1}'.format(
    'https' if env_https else 'http',
    str(uuid.uuid4())
)

# outgoing cookies + send headers
ocookies = cookies.BaseCookie()
crumbs = cookies.Morsel()
crumbs.set(cookie_name, setval, setval)
crumbs['httponly'] = True
crumbs['max-age'] = max_age
crumbs['secure'] = True
# crumbs['samesite'] = 'Strict' # todo: requires python 3.8+
ocookies[cookie_name] = crumbs
print(ocookies)
print('Content-type: {0};'.format(content_type))
print()

##################################################################
ctag('html')
ctag('body')
xprint('torbrowser onion secure cookie leak checker', tag='h1')
##################################################################

xprint('request context', tag='h2')
otag('ul')
kvprint('env_scheme', env_scheme, tag='li')
kvprint('env_port', env_port, tag='li')
kvprint('env_https', env_https, tag='li')
kvprint('env_uri', env_uri, tag='li')
kvprint('env_ua', env_ua, tag='li')
ctag('ul')

# incoming cookies
observed_set = False
observed_value = None
xprint('the client has supplied the following cookies', tag='h2')
otag('ul')
if env_cookie:
    icookies = cookies.BaseCookie(env_cookie)
    x = icookies.get(cookie_name, None)
    if x:
        observed_set = True
        observed_value = x.value
    for k in sorted(icookies.keys()):
        xprint(icookies[k].OutputString(), tag='li')
else:
    xprint('the client supplied no cookies', tag='li')
ctag('ul')

# outgoing cookies
xprint('this server has set the following cookies', tag='h2')
otag('ul')
for k in sorted(ocookies.keys()):
    xprint(ocookies[k].OutputString(), tag='li')
ctag('ul')

# expected
xprint('parameter-based expectations', tag='h2')
expected = cgi.FieldStorage().getfirst(cookie_name)
otag('ul')
if expected:
    kvprint('we expected a cookie with the value', expected, tag='li')
    if observed_set:
        kvprint('we observed a cookie with the value', observed_value, tag='li')
    else:
        xprint('we did not observe a cookie', tag='li')
else:
    xprint('according to parameters, we do not expect a cookie', tag='li')
ctag('ul')

##################################################################

xprint('analysis', tag='h2')
otag('ul')

if env_https:
    xprint('we are using HTTPS', tag='li')
else:
    xprint('we are NOT using HTTPS', tag='li')

if env_eotk:
    xprint('we are using onion networking', tag='li')
else:
    xprint('we are NOT using onion networking', tag='li')

if expected:
    xprint('we expected a secure cookie', tag='li')
else:
    xprint('we did not expect a secure cookie', tag='li')

if observed_set:
    xprint('we received a secure cookie', tag='li')
else:
    xprint('we did not receive a secure cookie', tag='li')

if expected and env_https and (not observed_set):
    xprint('we expected a secure cookie and are on HTTPS but did not receive one (stale request?)', tag='li')

if expected and (not env_https) and (not observed_set):
    xprint('we expected a secure cookie and are not on HTTPS and did not receive one (good)', tag='li')

if observed_set and expected and expected != observed_value:
    xprint('the secure cookie we received is not the expected value (stale request, or you upgraded from HTTP to HTTPS and got an old HTTPS value)', tag='li')

if observed_set and expected and expected == observed_value:
    xprint('the secure cookie received is the expected value (good)', tag='li')

if observed_set and env_https:
    xprint('the secure cookie was properly received over HTTPS (good)', tag='li')
    if observed_value.startswith('https:'):
        xprint('the secure cookie was issued over HTTPS and received over HTTPS (good)', tag='li')
    if observed_value.startswith('http:'):
        xprint('the secure cookie was issued over HTTP and received over HTTPS (bad, potential upgrade attack)', tag='li')

if observed_set and (not env_https):
    xprint('the secure cookie was received over HTTP (bad, depending on backend infrastructure)', tag='li')
    if observed_value.startswith('https:'):
        xprint('the secure cookie was issued over HTTPS but received over HTTP (bad, downgrade attack / data leak)', tag='li')
    if observed_value.startswith('http:'):
        xprint('the secure cookie was issued over HTTP and received over HTTP (neutral, but risky)', tag='li')

ctag('ul')

def link(scheme,
         server,
         desc,
         tag='li',
         path=uri_path,
         param='?{0}={1}'.format(cookie_name, setval)):
    return '<{tag}><a href="{scheme}://{server}{path}{param}">{desc}</a></{tag}>'.format(
        scheme=scheme,
        server=server,
        desc=desc,
        tag=tag,
        path=path,
        param=param
    )

xprint('potential test actions', tag='h2')
where = name_onion if env_eotk else name_dns
otag('ul')
print(link('http', where, 'test what happens when you click from here to the HTTP site'))
print(link('https', where, 'test what happens when you click from here to the HTTPS site'))
ctag('ul')

xprint('absolute navigation', tag='h2')
otag('ul')
print(link('https', name_onion, 'go to the https onion site', param=''))
print(link('http', name_onion, 'go to the http onion site', param=''))
print(link('https', name_dns, 'go to the https dns site', param=''))
print(link('http', name_dns, 'go to the http dns site', param=''))
ctag('ul')

##################################################################
ctag('body')
ctag('html')
##################################################################
