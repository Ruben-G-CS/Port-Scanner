import json
import socket
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8765
MAX_WORKERS = 100

PAGE = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Port Scanner</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 520px; margin: 30px auto; padding: 0 16px; }
  h1 { font-size: 20px; }
  label { display: block; margin-top: 12px; font-size: 13px; opacity: .8; }
  input { width: 100%; box-sizing: border-box; padding: 8px; font-size: 15px; margin-top: 4px; }
  .row { margin-top: 16px; display: flex; gap: 8px; }
  button { padding: 8px 16px; font-size: 15px; cursor: pointer; }
  progress { width: 100%; margin-top: 16px; height: 14px; }
  #status { margin-top: 8px; font-size: 14px; min-height: 20px; }
  #results { margin-top: 8px; font-family: Menlo, monospace; font-size: 14px; border: 1px solid #8884; border-radius: 6px; min-height: 160px; max-height: 320px; overflow-y: auto; padding: 8px; }
  #results div { padding: 2px 0; }
</style>
</head>
<body>
<h1>Port Scanner</h1>

<label>IP / host</label>
<input id="ip" value="127.0.0.1">

<label>Ports (80 or 1-1024)</label>
<input id="ports" value="1-1024">

<label>Timeout (ms)</label>
<input id="timeout" value="500">

<div class="row">
  <button id="scan">Scan</button>
  <button id="stop" disabled>Stop</button>
  <button id="clear">Clear</button>
</div>

<progress id="bar" value="0" max="100"></progress>
<div id="status">Ready</div>
<div id="results"></div>

<script>
const $ = id => document.getElementById(id);
const CHUNK = 500;
let stop = false, running = false;

function status(t) { $('status').textContent = t; }

$('clear').onclick = () => { $('results').innerHTML = ''; $('bar').value = 0; status('Ready'); };
$('stop').onclick = () => { stop = true; status('Stopping...'); };

$('scan').onclick = async () => {
  if (running) return;
  const ip = $('ip').value.trim();
  const m = $('ports').value.trim().match(/^(\d+)(?:-(\d+))?$/);
  const timeout = parseInt($('timeout').value);

  if (!ip) { status('Error: enter an IP or host'); return; }
  if (!m) { status('Error: ports must look like 80 or 1-1024'); return; }
  const lo = +m[1], hi = m[2] ? +m[2] : lo;
  if (lo < 1 || hi > 65535 || lo > hi) { status('Error: ports must be 1-65535'); return; }
  if (!(timeout > 0)) { status('Error: invalid timeout'); return; }

  running = true; stop = false;
  $('scan').disabled = true; $('stop').disabled = false;
  $('results').innerHTML = ''; $('bar').value = 0;
  status(`Scanning ${ip} ports ${lo}-${hi}...`);

  const total = hi - lo + 1;
  let done = 0, found = 0, failed = false;

  try {
    for (let s = lo; s <= hi && !stop; s += CHUNK) {
      const e = Math.min(s + CHUNK - 1, hi);
      const r = await fetch(`/scan?ip=${encodeURIComponent(ip)}&lo=${s}&hi=${e}&timeout=${timeout}`);
      const d = await r.json();
      if (d.error) { status('Error: ' + d.error); failed = true; break; }
      for (const p of d.open) {
        const div = document.createElement('div');
        div.textContent = p + '  OPEN';
        $('results').appendChild(div);
      }
      found += d.open.length;
      done += e - s + 1;
      $('bar').value = done / total * 100;
      status(`Scanned ${done}/${total}, ${found} open`);
    }
    if (!failed) status(`Done${stop ? ' (stopped)' : ''}. ${found} open port(s).`);
  } catch (err) {
    status('Error: ' + err);
  } finally {
    running = false;
    $('scan').disabled = false; $('stop').disabled = true;
  }
};
</script>
</body>
</html>
"""


def check(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj):
        self.send(code, json.dumps(obj), "application/json")

    def do_GET(self):
        url = urlparse(self.path)

        if url.path == "/":
            self.send(200, PAGE, "text/html; charset=utf-8")
            return

        if url.path == "/scan":
            q = parse_qs(url.query)
            try:
                host = q["ip"][0]
                lo = int(q["lo"][0])
                hi = int(q["hi"][0])
                timeout = int(q["timeout"][0]) / 1000
                if not (1 <= lo <= hi <= 65535) or timeout <= 0:
                    raise ValueError
            except (KeyError, ValueError, IndexError):
                self.send_json(400, {"error": "bad parameters"})
                return

            try:
                ip = socket.gethostbyname(host)
            except OSError:
                self.send_json(400, {"error": "invalid IP or host"})
                return

            ports = list(range(lo, hi + 1))
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                results = list(ex.map(lambda p: check(ip, p, timeout), ports))
            self.send_json(200, {"open": [p for p, ok in zip(ports, results) if ok]})
            return

        self.send(404, "Not found", "text/plain")


def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError:
        print(f"Port {PORT} is already in use. Close the other scanner window first.")
        return
    url = f"http://{HOST}:{PORT}"
    print(f"Port Scanner running at {url}  (Ctrl+C to quit)")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()