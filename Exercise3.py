import os
import socket
import sys
import gzip
import zlib
from urllib.parse import unquote

CRLF = b"\r\n"
END_HEADERS = b"\r\n\r\n"

SUPPORTED_METHODS = {"GET", "HEAD"}
SUPPORTED_ENCODINGS = {"gzip", "deflate"}

SERVER_NAME = "CIST-Python-HTTP/0.1"

def read_full_request_headers(conn, max_bytes=65536):
    """
    Poll a buffer until we have a complete HTTP request (headers end with \r\n\r\n).
    """
    conn.settimeout(2.0)
    data = b""

    while END_HEADERS not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk

        if len(data) > max_bytes:
            raise ValueError("Request too large")

    if END_HEADERS not in data:
        raise ValueError("Incomplete HTTP request headers")

    return data

def parse_request(raw_bytes):
    """
    Parses the request line and headers.
    Only accepts GET/HEAD and only supports Host and Accept-Encoding headers.
    """
    header_block = raw_bytes.split(END_HEADERS, 1)[0]
    lines = header_block.split(CRLF)

    #----- Start line -----
    if len(lines) < 1 or not lines[0]:
        raise ValueError("Missing request line")

    start_line = lines[0].decode("iso-8859-1")
    parts = start_line.split()

    #Must be: METHOD PATH HTTP/VERSION
    if len(parts) != 3:
        raise ValueError("Bad start-line format (expected: METHOD PATH HTTP/1.1)")

    method, path, version = parts

    if method not in SUPPORTED_METHODS:
        raise ValueError(f"Unsupported method: {method}")

    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise ValueError(f"Unsupported HTTP version: {version}")

    #----- Headers -----
    headers = {}
    for line in lines[1:]:
        if line == b"":
            break  #end of headers

        if b":" not in line:
            raise ValueError("Bad header format (missing ':')")

        name, value = line.split(b":", 1)
        name = name.decode("iso-8859-1").strip().lower()
        value = value.decode("iso-8859-1").strip()

        if not name:
            raise ValueError("Header name was empty")

        headers[name] = value

    #HTTP/1.1 should have Host
    if version == "HTTP/1.1" and "host" not in headers:
        raise ValueError("Missing Host header (required for HTTP/1.1)")

    #Only allow these headers
    for h in headers:
        if h not in ("host", "accept-encoding"):
            raise ValueError(f"Unsupported header: {h}")

    #Check Accept-Encoding
    encoding_choice = None
    if "accept-encoding" in headers:
        enc_list = [e.strip().lower() for e in headers["accept-encoding"].split(",") if e.strip()]

        #If any encoding listed is not supported, identify it
        for enc in enc_list:
            if enc not in SUPPORTED_ENCODINGS:
                raise ValueError(f"Unsupported Accept-Encoding: {enc}")

        #Choose one (prefer gzip)
        if "gzip" in enc_list:
            encoding_choice = "gzip"
        elif "deflate" in enc_list:
            encoding_choice = "deflate"

    return method, path, version, headers, encoding_choice

def safe_file_path(docroot, url_path):
    """
    Map /something to a safe file path inside docroot.
    Prevents directory traversal like /../../etc/passwd
    """
    #Remove query string
    url_path = url_path.split("?", 1)[0]
    url_path = unquote(url_path)

    if not url_path.startswith("/"):
        raise ValueError("Path must start with '/'")

    if url_path == "/":
        url_path = "/index.html"

    rel = os.path.normpath(url_path.lstrip("/"))

    #Block traversal attempts
    if rel.startswith("..") or os.path.isabs(rel):
        raise ValueError("Invalid path (possible traversal)")

    return os.path.join(docroot, rel)

def make_response(status_code, reason, headers, body_bytes):
    """
    Build a basic HTTP/1.1 response.
    """
    response_lines = [f"HTTP/1.1 {status_code} {reason}"]
    for k, v in headers.items():
        response_lines.append(f"{k}: {v}")
    response_lines.append("")  #Blank line
    response_lines.append("")  #Ensures \r\n\r\n

    head = "\r\n".join(response_lines).encode("iso-8859-1")
    return head + body_bytes

def handle_client(conn, addr, docroot):
    try:
        raw = read_full_request_headers(conn)
        method, path, version, headers, encoding_choice = parse_request(raw)

        filepath = safe_file_path(docroot, path)

        #File checks
        if not os.path.exists(filepath):
            body = b"404 Not Found\n"
            resp_headers = {
                "Server": SERVER_NAME,
                "Content-Type": "text/plain; charset=utf-8",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            conn.sendall(make_response(404, "Not Found", resp_headers, body if method == "GET" else b""))
            return

        if not os.path.isfile(filepath):
            body = b"403 Forbidden\n"
            resp_headers = {
                "Server": SERVER_NAME,
                "Content-Type": "text/plain; charset=utf-8",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            conn.sendall(make_response(403, "Forbidden", resp_headers, body if method == "GET" else b""))
            return

        try:
            with open(filepath, "rb") as f:
                body = f.read()
        except OSError:
            body = b"403 Forbidden\n"
            resp_headers = {
                "Server": SERVER_NAME,
                "Content-Type": "text/plain; charset=utf-8",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            conn.sendall(make_response(403, "Forbidden", resp_headers, body if method == "GET" else b""))
            return

        #Optional compression
        content_encoding = None
        out_body = body

        if encoding_choice == "gzip":
            out_body = gzip.compress(body)
            content_encoding = "gzip"
        elif encoding_choice == "deflate":
            out_body = zlib.compress(body)
            content_encoding = "deflate"

        resp_headers = {
            "Server": SERVER_NAME,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(out_body)),
            "Connection": "close",
        }
        if content_encoding:
            resp_headers["Content-Encoding"] = content_encoding

        #HEAD returns headers only
        if method == "HEAD":
            conn.sendall(make_response(200, "OK", resp_headers, b""))
        else:
            conn.sendall(make_response(200, "OK", resp_headers, out_body))

    except Exception as e:
        # Basic "safe" error response
        msg = f"400 Bad Request\n{e}\n".encode("utf-8")
        resp_headers = {
            "Server": SERVER_NAME,
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": str(len(msg)),
            "Connection": "close",
        }
        try:
            conn.sendall(make_response(400, "Bad Request", resp_headers, msg))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    port = 80
    docroot = os.getcwd()

    #Usage: python3 server.py [port] [docroot]
    if len(sys.argv) >= 2:
        port = int(sys.argv[1])
    if len(sys.argv) >= 3:
        docroot = sys.argv[2]

    if not os.path.isdir(docroot):
        print("Docroot must be a folder.")
        sys.exit(1)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(10)

    print(f"Serving on port {port} (docroot: {docroot})")
    print("Put an index.html file in this folder to test.")
    print("Ctrl+C to stop.")

    while True:
        conn, addr = server.accept()
        handle_client(conn, addr, docroot)

if __name__ == "__main__":
    main()
