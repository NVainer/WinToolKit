// A small HTTP/1.1 server over a raw TcpListener.
//
// Deliberately not HttpListener: that goes through http.sys, which refuses to
// bind a prefix unless the process is elevated or an admin has added a urlacl
// reservation.  On a locked-down machine that would make the console
// admin-only for no reason.  A plain TCP socket on the loopback needs neither.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace DeviceControlConsole
{
    public sealed class Request
    {
        public string Method = "";
        public string Path = "";
        public string RawQuery = "";
        public Dictionary<string, string> Headers =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Query =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string Body = "";

        public string Header(string name)
        {
            string value;
            return Headers.TryGetValue(name, out value) ? value : "";
        }

        public string Q(string name)
        {
            string value;
            return Query.TryGetValue(name, out value) ? value : "";
        }
    }

    public sealed class Response
    {
        public int Status = 200;
        public string ContentType = "text/plain; charset=utf-8";
        public byte[] Body = new byte[0];
        public Dictionary<string, string> Extra = new Dictionary<string, string>(StringComparer.Ordinal);

        public static Response Json(object value, int status)
        {
            Response r = new Response();
            r.Status = status;
            r.ContentType = "application/json; charset=utf-8";
            r.Body = Encoding.UTF8.GetBytes(DeviceControlConsole.Json.Write(value));
            return r;
        }

        public static Response Error(string message, int status)
        {
            Dictionary<string, object> m = DeviceControlConsole.Json.Obj();
            m["error"] = message;
            return Json(m, status);
        }

        public static Response Bytes(byte[] body, string contentType)
        {
            Response r = new Response();
            r.Body = body;
            r.ContentType = contentType;
            return r;
        }

        public static Response Text(string body, string contentType)
        {
            return Bytes(Encoding.UTF8.GetBytes(body), contentType);
        }
    }

    public sealed class HttpServer
    {
        private readonly IPAddress _address;
        private readonly int _port;
        private readonly Func<Request, Response> _handler;
        private TcpListener _listener;
        private volatile bool _running;

        public HttpServer(string host, int port, Func<Request, Response> handler)
        {
            _address = IPAddress.Parse(host);
            _port = port;
            _handler = handler;
        }

        /// <summary>Binds, retrying while a previous instance releases the port.</summary>
        public void Bind(int attempts, int delayMs)
        {
            SocketException last = null;
            for (int i = 0; i < attempts; i++)
            {
                try
                {
                    TcpListener listener = new TcpListener(_address, _port);
                    listener.ExclusiveAddressUse = true;  // never silently share the port
                    listener.Start(64);
                    _listener = listener;
                    return;
                }
                catch (SocketException ex)
                {
                    last = ex;
                    Thread.Sleep(delayMs);
                }
            }
            throw new IOException("could not bind " + _address + ":" + _port +
                (last == null ? "" : " -- " + last.Message));
        }

        public void Serve()
        {
            _running = true;
            while (_running)
            {
                TcpClient client;
                try { client = _listener.AcceptTcpClient(); }
                catch (SocketException) { break; }
                // ObjectDisposedException derives from InvalidOperationException,
                // so it has to be caught first.
                catch (ObjectDisposedException) { break; }
                catch (InvalidOperationException) { break; }

                TcpClient captured = client;
                ThreadPool.QueueUserWorkItem(delegate (object unused) { Handle(captured); });
            }
        }

        public void Stop()
        {
            _running = false;
            try { if (_listener != null) _listener.Stop(); } catch (SocketException) { }
        }

        private void Handle(TcpClient client)
        {
            try
            {
                using (client)
                {
                    client.ReceiveTimeout = 30000;
                    client.SendTimeout = 120000;
                    using (NetworkStream stream = client.GetStream())
                    {
                        Request request = ReadRequest(stream);
                        if (request == null) return;
                        Response response;
                        try { response = _handler(request); }
                        catch (Exception ex)
                        {
                            response = Response.Error(ex.GetType().Name + ": " + ex.Message, 500);
                        }
                        Write(stream, request, response);
                    }
                }
            }
            catch (IOException) { /* client hung up */ }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
        }

        // ------------------------------------------------------- parsing
        private static Request ReadRequest(NetworkStream stream)
        {
            List<byte> head = new List<byte>(2048);
            int matched = 0;
            byte[] one = new byte[1];
            while (matched < 4)
            {
                int read = stream.Read(one, 0, 1);
                if (read <= 0) return null;
                byte b = one[0];
                head.Add(b);
                // look for CR LF CR LF
                if ((matched == 0 || matched == 2) && b == 13) matched++;
                else if ((matched == 1 || matched == 3) && b == 10) matched++;
                else matched = (b == 13) ? 1 : 0;
                if (head.Count > 65536) return null;   // refuse an oversized header
            }

            string headText = Encoding.UTF8.GetString(head.ToArray(), 0, head.Count);
            string[] lines = headText.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) return null;

            string[] parts = lines[0].Split(' ');
            if (parts.Length < 2) return null;

            Request request = new Request();
            request.Method = parts[0].ToUpperInvariant();
            string target = parts[1];
            int question = target.IndexOf('?');
            if (question >= 0)
            {
                request.Path = UrlDecode(target.Substring(0, question));
                request.RawQuery = target.Substring(question + 1);
                ParseQuery(request.RawQuery, request.Query);
            }
            else request.Path = UrlDecode(target);

            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (line.Length == 0) continue;
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                request.Headers[line.Substring(0, colon).Trim()] = line.Substring(colon + 1).Trim();
            }

            int length;
            if (int.TryParse(request.Header("Content-Length"), out length) && length > 0)
            {
                if (length > 8 * 1024 * 1024) return null;
                byte[] body = new byte[length];
                int got = 0;
                while (got < length)
                {
                    int read = stream.Read(body, got, length - got);
                    if (read <= 0) break;
                    got += read;
                }
                request.Body = Encoding.UTF8.GetString(body, 0, got);
            }
            return request;
        }

        private static void ParseQuery(string raw, Dictionary<string, string> into)
        {
            foreach (string pair in raw.Split('&'))
            {
                if (pair.Length == 0) continue;
                int eq = pair.IndexOf('=');
                if (eq < 0) into[UrlDecode(pair)] = "";
                else into[UrlDecode(pair.Substring(0, eq))] = UrlDecode(pair.Substring(eq + 1));
            }
        }

        public static string UrlDecode(string s)
        {
            if (s.IndexOf('%') < 0 && s.IndexOf('+') < 0) return s;
            List<byte> bytes = new List<byte>(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '+') bytes.Add((byte)' ');
                else if (c == '%' && i + 2 < s.Length)
                {
                    int value;
                    if (int.TryParse(s.Substring(i + 1, 2), System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out value))
                    {
                        bytes.Add((byte)value);
                        i += 2;
                    }
                    else bytes.Add((byte)c);
                }
                else bytes.AddRange(Encoding.UTF8.GetBytes(c.ToString()));
            }
            return Encoding.UTF8.GetString(bytes.ToArray());
        }

        // ------------------------------------------------------- writing
        private static void Write(NetworkStream stream, Request request, Response response)
        {
            StringBuilder head = new StringBuilder();
            head.Append("HTTP/1.1 ").Append(response.Status).Append(' ')
                .Append(StatusText(response.Status)).Append("\r\n");
            head.Append("Content-Type: ").Append(response.ContentType).Append("\r\n");
            head.Append("Content-Length: ").Append(response.Body.Length).Append("\r\n");
            head.Append("Cache-Control: no-store\r\n");
            head.Append("X-Content-Type-Options: nosniff\r\n");
            head.Append("Referrer-Policy: no-referrer\r\n");
            head.Append("Connection: close\r\n");
            foreach (KeyValuePair<string, string> kv in response.Extra)
                head.Append(kv.Key).Append(": ").Append(kv.Value).Append("\r\n");
            head.Append("\r\n");

            byte[] headBytes = Encoding.UTF8.GetBytes(head.ToString());
            stream.Write(headBytes, 0, headBytes.Length);
            if (request.Method != "HEAD" && response.Body.Length > 0)
                stream.Write(response.Body, 0, response.Body.Length);
            stream.Flush();
        }

        private static string StatusText(int status)
        {
            switch (status)
            {
                case 200: return "OK";
                case 204: return "No Content";
                case 400: return "Bad Request";
                case 403: return "Forbidden";
                case 404: return "Not Found";
                case 405: return "Method Not Allowed";
                case 500: return "Internal Server Error";
                default: return "OK";
            }
        }
    }
}
