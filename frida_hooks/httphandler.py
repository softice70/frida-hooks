from http.server import BaseHTTPRequestHandler
import urllib
import json
from frida_hooks.scriptor import Scriptor


class HttpHandler(BaseHTTPRequestHandler):
    _agent = None

    @staticmethod
    def set_agent(agent):
        HttpHandler._agent = agent

    def _response(self, code, msg, data):
        ret_val = {'code': code, 'msg': msg, 'data': data}
        self.send_response(200)
        self.send_header('Content-type', 'text/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(ret_val, ensure_ascii=False).encode())

    def do_POST(self):
        cmd = urllib.parse.urlparse(self.path).path[1:]
        code = 0
        msg = ''
        data = {}
        if cmd == 'run':
            params_str = self.rfile.read(int(self.headers['content-length'])).decode("utf-8")
            params = json.loads(params_str)
            try:
                script = Scriptor.prepare_script(params, None)
                if script:
                    data = self._agent.exec_one_script(script)
                    try:
                        data = json.loads(data)
                    except Exception:
                        data = {'ret': data}
                else:
                    code = 3
                    msg = f'parse command error! rpc command: {cmd}, params: {params_str}'
            except Exception as e:
                code = 2
                msg = str(e)
        else:
            code = 1
            msg = f'invalidate url!'
        self._response(code, msg, data)

    def do_GET(self):
        self._response(-1, 'not support GET method!', {})


