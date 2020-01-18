# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
import traceback
from io import BytesIO

import vcr
import six
import ipaddress
from vcr.request import Request
from vcr.util import CaseInsensitiveDict
from vcr.persisters.filesystem import FilesystemPersister
from vcr.serialize import serialize
from vcr import VCR
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser


if sys.argv[1:]:
    vcr_method = sys.argv[1]
else:
    vcr_method = 'none'

PROXY_PY_DIR = os.path.dirname(os.path.realpath(__file__))
PROXY_PY_START_TIME = time.time()

VERSION = (1, 1, 1)
__version__ = '.'.join(map(str, VERSION[0:3]))
__description__ = 'Lightweight, Programmable, TLS interceptor Proxy for HTTP(S), HTTP2, ' \
                  'WebSockets protocols in a single Python file.'
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__download_url__ = '%s/archive/master.zip' % __homepage__
__license__ = 'BSD'

# Defaults
DEFAULT_BACKLOG = 100
DEFAULT_BASIC_AUTH = None
DEFAULT_CA_KEY_FILE = None
DEFAULT_CA_CERT_DIR = None
DEFAULT_CA_CERT_FILE = None
DEFAULT_CA_SIGNING_KEY_FILE = None
DEFAULT_CERT_FILE = None
DEFAULT_BUFFER_SIZE = 1024 * 1024
DEFAULT_CLIENT_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_SERVER_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_DISABLE_HEADERS = []
DEFAULT_IPV4_HOSTNAME = ipaddress.IPv4Address('127.0.0.1')
DEFAULT_IPV6_HOSTNAME = ipaddress.IPv6Address('::1')
DEFAULT_KEY_FILE = None
DEFAULT_PORT = 8080
DEFAULT_DISABLE_HTTP_PROXY = False
DEFAULT_ENABLE_DEVTOOLS = False
DEFAULT_DEVTOOLS_WS_PATH = b'/devtools'
DEFAULT_ENABLE_STATIC_SERVER = False
DEFAULT_ENABLE_WEB_SERVER = False
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_OPEN_FILE_LIMIT = 1024
DEFAULT_PAC_FILE = None
DEFAULT_PAC_FILE_URL_PATH = b'/'
DEFAULT_PID_FILE = None
DEFAULT_NUM_WORKERS = 0
DEFAULT_PLUGINS = ''    # Comma separated list of plugins
DEFAULT_STATIC_SERVER_DIR = os.path.join(PROXY_PY_DIR, 'public')
DEFAULT_VERSION = False
DEFAULT_LOG_FORMAT = '%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s'
DEFAULT_LOG_FILE = None
UNDER_TEST = False  # Set to True if under test


def bytes_(s, encoding = 'utf-8', errors = 'strict'):
    """Utility to ensure binary-like usability.

    If s is type str or int, return s.encode(encoding, errors),
    otherwise return s as it is."""
    if isinstance(s, bytes):
        return s
    if isinstance(s, int):
        s = str(s)
    if isinstance(s, str):
        return s.encode(encoding, errors)
    return s


version = bytes_(__version__)
CRLF, COLON, WHITESPACE, COMMA, DOT = b'\r\n', b':', b' ', b',', b'.'
PROXY_AGENT_HEADER_KEY = b'Proxy-agent'
PROXY_AGENT_HEADER_VALUE = b'proxy.py v' + version
PROXY_AGENT_HEADER = PROXY_AGENT_HEADER_KEY + \
    COLON + WHITESPACE + PROXY_AGENT_HEADER_VALUE


def build_http_response(status_code,
                        protocol_version = b'HTTP/1.1',
                        reason = None,
                        headers = None,
                        body = None):
    """Build and returns a HTTP response packet."""
    line = [protocol_version, bytes_(status_code)]
    if reason:
        line.append(reason)
    if headers is None:
        headers = {}
    if body is not None and not any(
            k.lower() == b'content-length' for k in headers):
        headers[b'Content-Length'] = bytes_(len(body))
    return build_http_pkt(line, headers, body)


def build_http_header(k, v):
    """Build and return a HTTP header line for use in raw packet."""
    val_str = v
    if isinstance(v, list):
        val_str = v[0]
    if isinstance(val_str, bytes):
        val_str = str(val_str)
    return k + COLON + WHITESPACE + val_str


def build_http_pkt(line,
                   headers=None,
                   body=None):
    """Build and returns a HTTP request or response packet."""
    req = WHITESPACE.join(line) + CRLF
    if headers is not None:
        for k in headers:
            req += build_http_header(k, headers[k]) + CRLF
    req += CRLF
    if body:
        req += body
    return req


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


def serialize_request_headers(request):
    headers = CaseInsensitiveDict()
    for k, v in request.headers.items():
        headers[k.decode()] = v

    return headers


def package_vcr_request(request, request_body):
    req = Request(method=request.command,
                  uri=request.path,
                  body=request_body,
                  headers=serialize_request_headers(request))
    return req


def compat_get_headers(message):
    for key in set(message.keys()):
        if six.PY3:
            yield key, message.get_all(key)
        else:
            yield key, message.getheaders(key)


def serialize_response_headers(response):
    out = {}
    for key, values in compat_get_headers(response.msg):
        out.setdefault(key, [])
        out[key].extend(values)
    return out


def response_to_dict(response, res_body):
    response_dict = {
        "status": {"code": response.status, "message": response.reason},
        "headers": serialize_response_headers(response),
        "body": {"string": res_body},
    }
    return response_dict


class FakeSocket:
    def __init__(self, response_bytes):
        try:
            response_str = response_bytes.decode()
            self._file = BytesIO(response_str.encode())
        except UnicodeDecodeError as err:
            self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file


def str_to_response(response_str):
    source = FakeSocket(bytes_(response_str))
    response = httplib.HTTPResponse(source)
    response.begin()
    return response


server_on = True
print id(server_on)

buffered_request_list = []
buffered_response_list = []
global_instance_lock = threading.Lock()
class MyPersister(FilesystemPersister):

    entercount = 0
    writecount = 0
    errorcount = 0

    @classmethod
    def load_cassette(cls, cassette_path, serializer):
        with global_instance_lock:
            global buffered_request_list
            global buffered_response_list
            if len(buffered_request_list) == 0 or len(buffered_response_list) == 0:
                buffered_request_list, buffered_response_list = FilesystemPersister.load_cassette(cassette_path, serializer)
            return buffered_request_list, buffered_response_list

    @staticmethod
    def save_cassette(cassette_path, cassette_dict, serializer):
        if 'none' == vcr_method:
            return
        with global_instance_lock:
            try:
                global buffered_request_list
                global buffered_response_list
                if len(cassette_dict['requests']) > len(buffered_request_list):
                    buffered_request_list = cassette_dict['requests']
                    buffered_response_list = cassette_dict['responses']

                MyPersister.entercount += 1
                data = serialize(cassette_dict, serializer)
                dirname, filename = os.path.split(cassette_path)
                if dirname and not os.path.exists(dirname):
                    os.makedirs(dirname)
                with open(cassette_path, "w") as f:
                    MyPersister.writecount += 1
                    f.write(data)
            except Exception as err:
                MyPersister.errorcount += 1
                traceback.print_exc()
                raise err

exclude_config = None
def load_exclude():
    filename = "exclude.json"
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            config = f.read()
        global exclude_config
        exclude_config = json.loads(config)


load_exclude()


def raw_body_match_on(r1, r2):
    global exclude_config
    if exclude_config and exclude_config.get('raw_body'):
        if r1.path in exclude_config.get('raw_body'):
            assert True
        else:
            assert vcr.util.read_body(r1) == vcr.util.read_body(r2)
    else:
        assert vcr.util.read_body(r1) == vcr.util.read_body(r2)


def cookie_match_on(r1, r2):
    c1 = r1.headers.get("cookie", "")
    c2 = r2.headers.get("cookie", "")

    assert r2.method == "GET" or c1 == c2 or c1 == "", "cookie {} != {}".format(r1.uri, r2.uri)


def query_match_on(r1, r2):
    global exclude_config
    r1q = []
    r2q = []
    if exclude_config and exclude_config.get('query'):
        if exclude_config['query'].get(r1.path):
            for q in r1.query:
                if not q[0] in exclude_config['query'][r1.path]:
                    r1q.append(q)
        if exclude_config['query'].get(r2.path):
            for q in r2.query:
                if not q[0] in exclude_config['query'][r2.path]:
                    r2q.append(q)
            print r2.query, r1.query
    else:
        r1q = r1.query
        r2q = r2.query

    assert r1q == r2q, "{} != {}".format(r1.uri, r2.uri)


class VCRProcess:
    _instance_lock = threading.Lock()
    cass_decorator = None

    def __init__(self, record_mode='all'):
        self.list = []
        self.done = False
        self.record_mode = record_mode
        self.get_cass_decorator()
        self.t = threading.Thread(target=self.run, args=())
        self.t.start()
        print 'cass start in model ' + self.record_mode

    # def set_record_mode(self, record_mode):
    #     self.record_mode = record_mode
    #     try:
    #         if self.cass_decorator:
    #             self.cass_decorator.close()
    #     except Exception:
    #         print 'close last cass error'
    #     self.cass_decorator = vcr.use_cassette('record/oneconnect_record.yaml', record_mode=self.record_mode)

    def get_cass_decorator(self):
        if not self.cass_decorator:
            my_vcr = VCR()
            my_vcr.register_persister(MyPersister)
            my_vcr.register_matcher('query_match_on', query_match_on)
            my_vcr.register_matcher('cookie_match_on', cookie_match_on)
            my_vcr.register_matcher('raw_body_match_on', raw_body_match_on)
            self.cass_decorator = my_vcr.use_cassette(
                'record/oneconnect_record.yaml',
                record_mode=self.record_mode,
                match_on=['query_match_on', 'method', 'scheme', 'host', 'port', 'path', 'cookie_match_on', 'raw_body_match_on']
                )
        return self.cass_decorator

    def read(self, request):
        with self._instance_lock:
            send_res = build_http_response(
                        404,
                        reason=b'NOT FOUND', body=b'Not Found'
                    )
            body = b'Not Found'
            # cass_decorator = vcr.use_cassette('record/thread1.yaml', record_mode='none', match_on=['uri', 'method', 'headers', 'body'])
            try:
                cass = self.get_cass_decorator().__enter__()
                if cass.can_play_response_for(request):
                    print "Playing response for {} from cassette".format(request)
                    response = cass.play_response(request)
                    send_res = build_http_response(
                        int(response['status']['code']),
                        reason=bytes_(response['status']['message']),
                        body=response['body']['string'],
                        headers=response['headers']
                    )
                    body = bytes_(response['body']['string'])
            finally:
                self.get_cass_decorator().__exit__()

            return send_res, body

    def put(self, request, response):
        self.list.append((request, response))

    def run(self):
        entercount = 0
        errorcount = 0
        exitcount = 0
        global server_on
        while server_on:
            try:
                if len(self.list) == 0:
                    time.sleep(2)
                    continue
            except KeyboardInterrupt:
                print "stop server"
                server_on = False
            try:
                entercount += 1
                cass = self.get_cass_decorator().__enter__()
                request, response = self.list.pop()
                cass.append(request, response)
            except KeyboardInterrupt:
                print "stop server"
                server_on = False
            except Exception as err:
                print "error: %s" % err
                errorcount += 1
            finally:
                try:
                    print "-------write yaml---------"
                    print "-------rest:"+ len(self.list) +"--------"
                    self.get_cass_decorator().__exit__()
                    exitcount += 1
                except Exception as err1:
                    print "exit err: %s" % err1

        print "finally entercount %d errorcount %d exitcount %d" % (entercount, errorcount, exitcount)


# VCR_PROCESS = VCRProcess()

vcr_process = VCRProcess(vcr_method)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    if sys.argv[2:]:
        vcr_host = sys.argv[2]
    else:
        vcr_host = 'wiki.ros.org'

    if sys.argv[3:]:
        proxy_address = sys.argv[3].split(':')
    else:
        proxy_address = None



    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        global vcr_process
        self.vcr_process = vcr_process
        global vcr_method
        self.vcr_method = vcr_method
        print 'init ProxyRequest'
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        # self.send_error(502)
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return
        print '-----------start new request-------------'
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        packaged_request = package_vcr_request(req, req_body)
        if self.vcr_method == 'none':
            """播放"""
            print '-----------play request-------------'
            response_str, res_body = self.vcr_process.read(packaged_request)
            res = str_to_response(response_str)
            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            # res_body = res.read()

        elif self.vcr_method == 'all':
            """录制"""

            if netloc != self.vcr_host:
                return
            try:
                origin = (scheme, netloc)
                req_headers = dict(
                    (k.encode('ascii') if isinstance(k, unicode) else k,
                     v.encode('ascii') if isinstance(v, unicode) else v)
                    for k, v in req.headers.items())

                if self.proxy_address is None:
                    if not origin in self.tls.conns:
                        if scheme == 'https':
                            self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                        else:
                            self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
                    conn = self.tls.conns[origin]
                    conn.request(self.command, path, req_body, req_headers)
                else:
                    if not origin in self.tls.conns:
                        if scheme == 'https':
                            self.tls.conns[origin] = httplib.HTTPSConnection(self.proxy_address[0], int(self.proxy_address[1]), timeout=self.timeout)
                        else:
                            self.tls.conns[origin] = httplib.HTTPConnection(self.proxy_address[0], int(self.proxy_address[1]), timeout=self.timeout)
                    conn = self.tls.conns[origin]
                    conn.request(self.command, req.path, req_body, dict(req.headers))
                res = conn.getresponse()

                version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
                setattr(res, 'headers', res.msg)
                setattr(res, 'response_version', version_table[res.version] if res.version else version_table[10])

                # support streaming
                if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                    self.response_handler(req, req_body, res, '')
                    setattr(res, 'headers', self.filter_headers(res.headers))
                    self.relay_streaming(res)
                    with self.lock:
                        self.save_handler(req, req_body, res, '')
                    return

                res_body = res.read()
            except Exception as e:
                traceback.print_exc()
                if origin in self.tls.conns:
                    del self.tls.conns[origin]
                self.send_error(502)
                return

            response_dict = response_to_dict(res, res_body)
            self.vcr_process.put(packaged_request, response_dict)

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)

        print data
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        try:
            #self.print_info(req, req_body, res, res_body)
            pass
        except Exception as err:
            print('[error] print_info error')


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    # if sys.argv[1:]:
    #     port = int(sys.argv[1])
    # else:
    #     port = 8080
    port = 8080
    server_address = ('::1', port)
    print 'start'


    try:
        HandlerClass.protocol_version = protocol
        httpd = ServerClass(server_address, HandlerClass)
        sa = httpd.socket.getsockname()

        print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
        httpd.serve_forever()
    except Exception:
        global server_on
        server_on = False
        print 'stoped'
        traceback.print_exc()


if __name__ == '__main__':
    test()
