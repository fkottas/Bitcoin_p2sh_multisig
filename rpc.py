import base64, json, os, pathlib, urllib.request

def default_cookie_path(network: str) -> str:
    appdata = os.environ.get("APPDATA")
    base = pathlib.Path(appdata) / "Bitcoin"
    if network == "regtest": return str(base / "regtest" / ".cookie")
    if network == "testnet": return str(base / "testnet3" / ".cookie")
    if network == "signet":  return str(base / "signet" / ".cookie")
    raise RuntimeError("bad network")

class BitcoinRPC:
    def __init__(self, host: str, port: int, cookie_path: str):
        self.host, self.port, self.cookie_path = host, port, cookie_path
        self._id = 0

    def _auth_header(self) -> str:
        raw = pathlib.Path(self.cookie_path).read_text().strip()
        token = base64.b64encode(raw.encode()).decode()
        return "Basic " + token

    def call(self, method: str, params=None):
        if params is None:
            params = []
        self._id += 1
        payload = json.dumps({"jsonrpc":"1.0","id":self._id,"method":method,"params":params}).encode()
        req = urllib.request.Request(
            f"http://{self.host}:{self.port}/",
            data=payload,
            headers={"Content-Type":"application/json","Authorization": self._auth_header()},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                out = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            # Read JSON error body from bitcoind
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {body}") from None
    
        if out.get("error"):
            raise RuntimeError(out["error"])
        return out["result"]


