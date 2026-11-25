from http.server import BaseHTTPRequestHandler, HTTPServer


class LabHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        corpo = f"<h1>Laboratorio Redes - demo.lab</h1><p>Rota: {self.path}</p>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_POST(self):
        tamanho = int(self.headers.get("Content-Length", 0))
        dados_recebidos = self.rfile.read(tamanho).decode("utf-8", errors="replace")
        resposta = f'{{"status": "ok", "rota": "{self.path}", "echo": "{dados_recebidos}"}}'.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(resposta)))
        self.end_headers()
        self.wfile.write(resposta)


if __name__ == "__main__":
    servidor = HTTPServer(("0.0.0.0", 80), LabHTTPHandler)
    print("[*] Servidor HTTP ativo em TCP/80 (rotas GET / e POST /echo)...")
    servidor.serve_forever()