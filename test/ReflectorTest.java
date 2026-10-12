package burp;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.*;

/**
 * Runs the real extension classes against a fake Burp API and a tiny simulated vulnerable app.
 * Usage: see build.sh test
 */
public class ReflectorTest {
    static int failures = 0;
    static final AtomicInteger probes = new AtomicInteger();
    static final List<String> errors = new CopyOnWriteArrayList<>();
    static final List<String> probeRequests = new CopyOnWriteArrayList<>();
    static final List<String> registered = new CopyOnWriteArrayList<>();
    static boolean inScope = true;
    static volatile String[] burpVersion = null;
    static volatile long probeDelayMs = 0;

    static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS  " : "FAIL  ") + name);
        if (!ok) failures++;
    }

    // ---------- fake Burp API ----------
    static String str(byte[] b) { return new String(b, StandardCharsets.ISO_8859_1); }
    static byte[] bytes(String s) { return s.getBytes(StandardCharsets.ISO_8859_1); }

    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> iface, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class[]{iface}, (p, m, a) -> {
            if (values.containsKey(m.getName())) return values.get(m.getName());
            if (m.getName().equals("toString")) return iface.getSimpleName();
            return null;
        });
    }

    static IHttpService service() {
        Map<String, Object> m = new HashMap<>();
        m.put("getHost", "app.test"); m.put("getPort", 80); m.put("getProtocol", "http");
        return stub(IHttpService.class, m);
    }

    static IHttpRequestResponse rr(byte[] req, byte[] resp) {
        Map<String, Object> m = new HashMap<>();
        m.put("getRequest", req); m.put("getResponse", resp); m.put("getHttpService", service());
        return stub(IHttpRequestResponse.class, m);
    }

    static IParameter param(String name, String value, byte type, int s, int e) {
        Map<String, Object> m = new HashMap<>();
        m.put("getName", name); m.put("getValue", value); m.put("getType", type);
        m.put("getValueStart", s); m.put("getValueEnd", e);
        return stub(IParameter.class, m);
    }

    static IRequestInfo analyzeRequest(byte[] req) throws Exception {
        String r = str(req);
        int bodyOffset = r.indexOf("\r\n\r\n") + 4;
        String[] lines = r.substring(0, bodyOffset - 4).split("\r\n");
        String[] first = lines[0].split(" ");
        List<IParameter> params = new ArrayList<>();
        int q = lines[0].indexOf('?');
        if (q != -1) {
            int end = lines[0].lastIndexOf(" HTTP");
            Matcher mm = Pattern.compile("([^&=?]+)=([^&]*)").matcher(lines[0].substring(q + 1, end));
            while (mm.find()) {
                int base = q + 1;
                params.add(param(mm.group(1), mm.group(2), IParameter.PARAM_URL, base + mm.start(2), base + mm.end(2)));
            }
        }
        String body = r.substring(bodyOffset);
        if (body.startsWith("{")) {
            Matcher mm = Pattern.compile("\"([^\"]+)\":(\"([^\"]*)\"|[0-9a-z]+)").matcher(body);
            while (mm.find()) {
                boolean quoted = mm.group(3) != null;
                int s = bodyOffset + (quoted ? mm.start(3) : mm.start(2));
                int e = bodyOffset + (quoted ? mm.end(3) : mm.end(2));
                params.add(param(mm.group(1), quoted ? mm.group(3) : mm.group(2), IParameter.PARAM_JSON, s, e));
            }
        } else if (!body.isEmpty()) {
            Matcher mm = Pattern.compile("([^&=]+)=([^&]*)").matcher(body);
            while (mm.find())
                params.add(param(mm.group(1), mm.group(2), IParameter.PARAM_BODY, bodyOffset + mm.start(2), bodyOffset + mm.end(2)));
        }
        Map<String, Object> m = new HashMap<>();
        m.put("getMethod", first[0]);
        m.put("getUrl", new URL("http://app.test" + first[1]));
        m.put("getHeaders", Arrays.asList(lines));
        m.put("getParameters", params);
        m.put("getBodyOffset", bodyOffset);
        return stub(IRequestInfo.class, m);
    }

    static IExtensionHelpers helpers() {
        Map<String, Object> m = new HashMap<>();
        // handler needs the arguments, so build it by hand
        return (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class[]{IExtensionHelpers.class}, (p, method, a) -> {
            switch (method.getName()) {
                case "analyzeRequest":
                    byte[] req = a[0] instanceof IHttpRequestResponse ? ((IHttpRequestResponse) a[0]).getRequest()
                            : (byte[]) a[a.length - 1];
                    return analyzeRequest(req);
                case "analyzeResponse": {
                    String r = str((byte[]) a[0]);
                    int off = r.indexOf("\r\n\r\n") + 4;
                    Map<String, Object> v = new HashMap<>();
                    v.put("getBodyOffset", off);
                    v.put("getHeaders", Arrays.asList(r.substring(0, Math.max(0, off - 4)).split("\r\n")));
                    return stub(IResponseInfo.class, v);
                }
                case "urlDecode":
                    if (a[0] instanceof byte[])
                        return bytes(java.net.URLDecoder.decode(str((byte[]) a[0]), "ISO-8859-1"));
                    return java.net.URLDecoder.decode((String) a[0], "ISO-8859-1");
                case "stringToBytes": return bytes((String) a[0]);
                case "bytesToString": return str((byte[]) a[0]);
                case "indexOf": {
                    byte[] data = (byte[]) a[0], pat = (byte[]) a[1];
                    boolean cs = (boolean) a[2];
                    int from = (int) a[3], to = (int) a[4];
                    String d = str(data), pt = str(pat);
                    if (!cs) { d = d.toLowerCase(); pt = pt.toLowerCase(); }
                    int idx = d.substring(0, to).indexOf(pt, from);
                    return idx;
                }
            }
            return null;
        });
    }

    static IBurpExtenderCallbacks callbacks(Map<String, String> settingsStore) {
        return (IBurpExtenderCallbacks) Proxy.newProxyInstance(IBurpExtenderCallbacks.class.getClassLoader(),
                new Class[]{IBurpExtenderCallbacks.class}, (p, method, a) -> {
            switch (method.getName()) {
                case "loadExtensionSetting": return settingsStore.get(a[0]);
                case "saveExtensionSetting": settingsStore.put((String) a[0], (String) a[1]); return null;
                case "isInScope": return inScope;
                case "getBurpVersion": return burpVersion;
                case "registerScannerCheck": case "registerHttpListener": case "addSuiteTab":
                case "registerExtensionStateListener": case "setExtensionName": case "customizeUiComponent":
                    registered.add(method.getName()); return null;
                case "createMessageEditor": {
                    final javax.swing.JPanel comp = new javax.swing.JPanel();
                    return stub(IMessageEditor.class, new HashMap<String, Object>() {{ put("getComponent", comp); }});
                }
                case "printError": errors.add(String.valueOf(a[0])); return null;
                case "applyMarkers": return stub(IHttpRequestResponseWithMarkers.class, new HashMap<>());
                case "getHelpers": return helpers();
                case "makeHttpRequest": {
                    probes.incrementAndGet();
                    if (probeDelayMs > 0) Thread.sleep(probeDelayMs);
                    byte[] req = (byte[]) a[1];
                    probeRequests.add(str(req));
                    return rr(req, app(str(req)));
                }
            }
            return null;
        });
    }

    // ---------- simulated vulnerable app ----------
    static String dec(String s) {
        try { return java.net.URLDecoder.decode(s.replace("+", " "), "ISO-8859-1"); } catch (Exception e) { return s; }
    }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    static byte[] app(String req) {
        // reject requests whose Content-Length does not match the body (what a real server would choke on)
        int off = req.indexOf("\r\n\r\n") + 4;
        Matcher cl = Pattern.compile("(?im)^content-length:\\s*(\\d+)").matcher(req.substring(0, off));
        if (cl.find() && Integer.parseInt(cl.group(1)) != req.length() - off)
            return bytes("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\nbad content-length");
        String line = req.split("\r\n")[0];
        String path = line.split(" ")[1];
        String val = "";
        String bodyStr = req.substring(off);
        Matcher qm = Pattern.compile("[?&]q=([^& ]*)").matcher(line);
        if (qm.find()) val = dec(qm.group(1));
        else if (bodyStr.startsWith("{")) {
            Matcher jm = Pattern.compile("\"(?:name|id)\":(\"((?:[^\"\\\\]|\\\\.)*)\"|[0-9a-z]+)").matcher(bodyStr);
            if (jm.find()) val = jm.group(2) != null ? jm.group(2).replace("\\\"", "\"") : jm.group(1);
        } else {
            Matcher fm = Pattern.compile("(?:^|&)q=([^&]*)").matcher(bodyStr);
            if (fm.find()) val = dec(fm.group(1));
        }
        String ua = "";
        Matcher um = Pattern.compile("(?im)^user-agent: (.*)$").matcher(req);
        if (um.find()) ua = um.group(1);
        String ct = "text/html", body;
        if (path.startsWith("/raw")) body = "<html><body><div>" + val + "</div></body></html>";
        else if (path.startsWith("/escaped")) body = "<html><body><div>" + esc(val) + "</div></body></html>";
        else if (path.startsWith("/attr")) body = "<html><body><input value=\"" + val + "\"></body></html>";
        else if (path.startsWith("/js")) body = "<html><script>var x='" + val + "';</script></html>";
        else if (path.startsWith("/ua")) body = "<html><body><footer>" + ua + "</footer></body></html>";
        else if (path.startsWith("/post")) body = "<html><body><p>" + val + "</p></body></html>";
        else if (path.startsWith("/nocontenttype")) { ct = null; body = "<div>" + val + "</div>"; }
        else if (path.startsWith("/jsonapi")) { ct = "application/json"; body = "{\"echo\":\"" + val + "\"}"; }
        else body = "<html>nothing</html>";
        return bytes("HTTP/1.1 200 OK\r\n" + (ct == null ? "" : "Content-Type: " + ct + "\r\n") + "\r\n" + body);
    }

    static byte[] get(String pathAndQuery, String extraHeaders) {
        return bytes("GET " + pathAndQuery + " HTTP/1.1\r\nHost: app.test\r\nUser-Agent: Mozilla/5.0 test\r\n" + extraHeaders + "\r\n");
    }

    static byte[] post(String path, String contentType, String body) {
        return bytes("POST " + path + " HTTP/1.1\r\nHost: app.test\r\nContent-Type: " + contentType
                + "\r\nContent-Length: " + body.length() + "\r\n\r\n" + body);
    }

    static BurpExtender extender(Map<String, String> store) throws Exception {
        BurpExtender e = new BurpExtender();
        IBurpExtenderCallbacks cb = callbacks(store);
        set(e, "callbacks", cb); set(e, "helpers", cb.getHelpers()); set(e, "settings", new Settings(cb));
        return e;
    }

    static void set(Object o, String f, Object v) throws Exception {
        Field fld = o.getClass().getDeclaredField(f);
        fld.setAccessible(true);
        fld.set(o, v);
    }

    static List<IScanIssue> scan(BurpExtender e, byte[] req) {
        return e.doPassiveScan(rr(req, app(str(req))));
    }

    static IScanIssue one(List<IScanIssue> l) { return l == null || l.isEmpty() ? null : l.get(0); }

    static IHttpRequestResponse recordingRR(byte[] req, String[] commentOut, String[] highlightOut) {
        return (IHttpRequestResponse) Proxy.newProxyInstance(IHttpRequestResponse.class.getClassLoader(),
                new Class[]{IHttpRequestResponse.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "getRequest": return req;
                case "getResponse": return app(str(req));
                case "getHttpService": return service();
                case "getComment": return commentOut[0];
                case "setComment": commentOut[0] = (String) a[0]; return null;
                case "setHighlight": highlightOut[0] = (String) a[0]; return null;
            }
            return null;
        });
    }

    static void waitIdle(BurpExtender e) throws Exception {
        for (int n = 0; n < 100 && e.pendingProbes() > 0; n++) Thread.sleep(50);
    }

    static void listenerTests() throws Exception {
        System.out.println("--- proxy listener / Community mode ---");
        burpVersion = new String[]{"Burp Suite Community Edition", "2024", "1"};
        check("Community: proxy listener is on by default", new Settings(callbacks(new HashMap<>())).getProxyListener());
        burpVersion = new String[]{"Burp Suite Professional", "2024", "1"};
        check("Professional: proxy listener is off by default", !new Settings(callbacks(new HashMap<>())).getProxyListener());
        burpVersion = new String[]{"Burp Suite Community Edition", "2024", "1"};

        Map<String, String> store = new HashMap<>();
        BurpExtender e = extender(store);
        ResultsPanel results = new ResultsPanel(callbacks(store));
        set(e, "results", results);
        String[] comment = {null}, highlight = {null};

        check("Scanner path does nothing while the listener is on", scan(e, get("/raw?q=hello", "")) == null);

        // proxy response -> highlight + comment immediately, row added
        probeDelayMs = 300;
        long t0 = System.currentTimeMillis();
        e.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, false, recordingRR(get("/raw?q=hello", ""), comment, highlight));
        long took = System.currentTimeMillis() - t0;
        check("listener returns before the (slow) probes finish, proxy is not blocked", took < 200 && e.pendingProbes() > 0);
        check("proxy history item highlighted orange", "orange".equals(highlight[0]));
        check("proxy history comment names the parameter", comment[0] != null && comment[0].contains("Reflector v2") && comment[0].contains("q"));
        check("row shows up as pending while probing", results.size() == 1 && results.snapshot().get(0).pending);
        waitIdle(e);
        probeDelayMs = 0;
        Finding f = results.snapshot().get(0);
        check("probe result filled in: High + allowed chars", !f.pending && f.vulnerable && f.severity().equals("High") && f.allowed.contains("<"));
        check("row has host, URL, parameter, location", f.host.equals("app.test") && f.url.contains("/raw?q=hello") && f.parameter.equals("q") && f.reflectedIn.equals("BODY"));
        check("row keeps the request and response for the viewer", f.message.getRequest() != null && f.message.getResponse() != null);

        // same page again: one row, not two, and no extra probes
        int before = probes.get();
        e.processHttpMessage(4, false, recordingRR(get("/raw?q=hello", ""), new String[1], new String[1]));
        waitIdle(e);
        check("revisiting the page keeps a single row and sends no new probes", results.size() == 1 && probes.get() == before);

        // escaped reflection => Medium
        e.processHttpMessage(4, false, recordingRR(get("/escaped?q=hello", ""), new String[1], new String[1]));
        waitIdle(e);
        Finding esc = null;
        for (Finding x : results.snapshot()) if (x.url.contains("/escaped")) esc = x;
        check("escaped reflection is listed as Medium", esc != null && !esc.vulnerable && esc.severity().equals("Medium"));

        // things that must be ignored
        int rows = results.size();
        e.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, recordingRR(get("/raw?q=zzz1", ""), new String[1], new String[1]));
        e.processHttpMessage(64, false, recordingRR(get("/raw?q=zzz2", ""), new String[1], new String[1]));
        inScope = false;
        e.processHttpMessage(4, false, recordingRR(get("/raw?q=zzz3", ""), new String[1], new String[1]));
        inScope = true;
        e.processHttpMessage(4, false, recordingRR(get("/nothing?q=zzz4", ""), new String[1], new String[1]));
        check("requests, non-proxy tools, out-of-scope and non-reflecting responses are ignored", results.size() == rows);

        // aggressive off => no probes, row is final at once
        store.put("Aggressive mode", "false");
        BurpExtender e2 = extender(store);
        ResultsPanel r2 = new ResultsPanel(callbacks(store));
        set(e2, "results", r2);
        before = probes.get();
        e2.processHttpMessage(4, false, recordingRR(get("/raw?q=hello", ""), new String[1], new String[1]));
        check("aggressive off: no probes, finished row at once", probes.get() == before && r2.size() == 1 && !r2.snapshot().get(0).pending && e2.pendingProbes() == 0);
        store.remove("Aggressive mode");

        r2.clear();
        check("Clear empties the table", r2.size() == 0);

        // Pro with the Scanner: issues still created and rows still listed
        burpVersion = new String[]{"Burp Suite Professional", "2024", "1"};
        Map<String, String> proStore = new HashMap<>();
        BurpExtender pro = extender(proStore);
        ResultsPanel rp = new ResultsPanel(callbacks(proStore));
        set(pro, "results", rp);
        IScanIssue i = one(scan(pro, get("/raw?q=prohello", "")));
        check("Pro: Scanner issue still raised", i != null && i.getIssueName().equals("XSS (vulnerable)"));
        check("Pro: the finding is also listed in the Results tab", rp.size() == 1 && rp.snapshot().get(0).vulnerable);
        pro.processHttpMessage(4, false, recordingRR(get("/raw?q=prohello2", ""), new String[1], new String[1]));
        check("Pro: listener stays off unless enabled", rp.size() == 1);
        burpVersion = null;
    }

    static void startupTests() throws Exception {
        System.out.println("--- extension startup (real UI wiring, headless) ---");
        for (boolean community : new boolean[]{true, false}) {
            burpVersion = new String[]{community ? "Burp Suite Community Edition" : "Burp Suite Professional", "2024", "1"};
            registered.clear();
            Map<String, String> store = new HashMap<>();
            BurpExtender e = new BurpExtender();
            e.registerExtenderCallbacks(callbacks(store));
            javax.swing.SwingUtilities.invokeAndWait(() -> {});
            for (int n = 0; n < 50 && !registered.contains("registerHttpListener"); n++) Thread.sleep(50);
            String label = community ? "Community" : "Pro";
            check(label + ": tab added and listener registered", registered.contains("addSuiteTab") && registered.contains("registerHttpListener"));
            check(label + ": Scanner check " + (community ? "NOT " : "") + "registered", registered.contains("registerScannerCheck") == !community);
            Object ui = e.getUiComponent();
            check(label + ": UI is a tabbed pane with Results + Settings", ui instanceof javax.swing.JTabbedPane
                    && ((javax.swing.JTabbedPane) ui).getTabCount() == 2
                    && ((javax.swing.JTabbedPane) ui).getTitleAt(0).equals("Results"));
            // the Proxy listener checkbox must write the setting
            Field cb = BurpExtender.class.getDeclaredField("proxyListener");
            cb.setAccessible(true);
            javax.swing.JCheckBox box = (javax.swing.JCheckBox) cb.get(e);
            check(label + ": checkbox reflects default", box.isSelected() == community);
            box.setSelected(!community);
            check(label + ": toggling checkbox saves the setting", store.get("Proxy listener").equals(String.valueOf(!community)));
            e.extensionUnloaded();
        }
        burpVersion = null;
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");
        Map<String, String> store = new HashMap<>();
        BurpExtender e = extender(store);

        // defaults
        check("default: scope-only is ON", Boolean.TRUE.equals(new Settings(callbacks(new HashMap<>())).getScopeOnly()));
        inScope = false;
        check("out-of-scope request is not scanned and sends no probes", scan(e, get("/raw?q=hello", "")) == null && probes.get() == 0);
        inScope = true;

        // basic reflection, unescaped -> vulnerable
        IScanIssue i = one(scan(e, get("/raw?q=hello", "")));
        check("raw reflection => XSS (vulnerable)/High", i != null && i.getIssueName().equals("XSS (vulnerable)") && i.getSeverity().equals("High"));
        check("details name the parameter and its allowed chars", i != null && i.getIssueDetail().contains("q - reflected 1 times") && i.getIssueDetail().contains("&lt;"));

        // HTML-escaped reflection -> found (previously missed? no, raw value matched) but only 'possible'
        i = one(scan(e, get("/escaped?q=a%26b%3Cc", "")));
        check("HTML-escaped reflection of a&b<c is detected (encoded variant)", i != null && i.getIssueDetail().contains("q - reflected"));
        check("escaped reflection is only 'possible'/Medium", i != null && i.getIssueName().equals("XSS (possible)") && i.getSeverity().equals("Medium"));

        // short value
        i = one(scan(e, get("/raw?q=ab", "")));
        check("2-char value is now tested", i != null);
        i = one(scan(e, get("/raw?q=a", "")));
        check("1-char value is still skipped", i == null);

        // JSON
        probeRequests.clear();
        byte[] jreq = post("/post", "application/json", "{\"id\":12345,\"name\":\"bob\"}");
        i = one(scan(e, jreq));
        check("JSON: numeric value (unquoted) detected", i != null && i.getIssueDetail().contains("id - reflected"));
        IScanIssue iq = one(scan(e, post("/post", "application/json", "{\"other\":1,\"name\":\"bob\"}")));
        check("JSON: quoted value detected", iq != null && iq.getIssueDetail().contains("name - reflected"));
        boolean validJson = !probeRequests.isEmpty();
        for (String pr : probeRequests) {
            String b = pr.substring(pr.indexOf("\r\n\r\n") + 4);
            // exactly balanced quotes after unescaping JSON escapes, and Content-Length accepted by the app
            validJson &= b.startsWith("{") && b.endsWith("}") && b.replace("\\\"", "").chars().filter(c -> c == '"').count() % 2 == 0;
        }
        check("JSON probes stay valid JSON (bare number is quoted)", validJson);
        check("JSON probe Content-Length is accepted (no 400 from app)", i != null && i.getIssueName().equals("XSS (vulnerable)"));

        // form body
        i = one(scan(e, post("/post", "application/x-www-form-urlencoded", "q=hello+there&x=1")));
        check("form body param probed with correct Content-Length", i != null && i.getIssueName().equals("XSS (vulnerable)"));

        // header
        i = one(scan(e, get("/ua", "")));
        check("User-Agent header reflection detected", i != null && i.getIssueDetail().contains("User-Agent"));

        // no content type
        i = one(scan(e, get("/nocontenttype?q=hello", "")));
        check("response without Content-Type is tested", i != null);

        // json response only when type enabled
        i = one(scan(e, get("/jsonapi?q=hello", "")));
        check("application/json responses tested by default", i != null);

        // context mode
        store.put("Check context", "true");
        BurpExtender ec = extender(store);
        i = one(scan(ec, get("/attr?q=zzz", "")));
        check("context mode: attribute context flagged VULNERABLE", i != null && i.getIssueDetail().contains("Attribute"));
        i = one(scan(ec, get("/js?q=zzz", "")));
        check("context mode: JS string context flagged", i != null && i.getIssueDetail().contains("Script str"));
        store.remove("Check context");

        // probe cache
        int before = probes.get();
        scan(e, get("/raw?q=hello", "")); scan(e, get("/raw?q=hello", ""));
        check("repeat scans of same endpoint+param send no new probes (cache)", probes.get() == before);

        // aggressive off => no probes
        store.put("Aggressive mode", "false");
        BurpExtender ea = extender(store);
        before = probes.get();
        i = one(scan(ea, get("/rawx?q=hello", "")));
        i = one(scan(ea, get("/raw?q=newvalue", "")));
        check("aggressive off: no probe requests, issue is 'possible'", probes.get() == before && i != null && i.getIssueName().equals("XSS (possible)"));
        store.remove("Aggressive mode");

        // null response must not throw
        boolean threw = false;
        try { e.doPassiveScan(rr(get("/raw?q=hello", ""), null)); } catch (Throwable t) { threw = true; }
        check("request without response does not throw", !threw);

        // thread safety of issue severity
        ExecutorService ex = Executors.newFixedThreadPool(16);
        List<Future<Boolean>> fs = new ArrayList<>();
        for (int n = 0; n < 400; n++) {
            final int k = n;
            fs.add(ex.submit(() -> {
                boolean vuln = k % 2 == 0;
                IScanIssue r = one(scan(e, get((vuln ? "/raw" : "/escaped") + "?q=thread" + (k % 5 == 0 ? "" : "x") + k, "")));
                return r != null && r.getIssueName().equals(vuln ? "XSS (vulnerable)" : "XSS (possible)");
            }));
        }
        boolean allOk = true;
        for (Future<Boolean> f : fs) allOk &= f.get();
        ex.shutdown();
        check("400 concurrent scans: severity never crosses between threads", allOk);
        check("no probe errors logged", errors.isEmpty());
        if (!errors.isEmpty()) System.out.println(errors);

        listenerTests();
        startupTests();

        System.out.println(failures == 0 ? "\nALL TESTS PASSED" : "\n" + failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
