package burp;

/** One reflected parameter on one URL, as shown in the Results tab. */
class Finding {
    final long time = System.currentTimeMillis();
    final String method;
    final String host;
    final String url;
    final String parameter;
    final String reflectedIn;
    final int count;
    final IHttpRequestResponse message;
    // filled in once the probe / context analysis has finished
    volatile String allowed = "";
    volatile boolean vulnerable = false;
    volatile boolean pending = false;

    Finding(String method, String host, String url, String parameter, String reflectedIn, int count, IHttpRequestResponse message) {
        this.method = method;
        this.host = host;
        this.url = url;
        this.parameter = parameter;
        this.reflectedIn = reflectedIn;
        this.count = count;
        this.message = message;
    }

    String key() {
        return method + " " + url + " " + parameter;
    }

    String severity() {
        return vulnerable ? "High" : "Medium";
    }

    /** the analysis result without the HTML the Scanner issue text uses */
    static String plain(String html) {
        if (html == null) return "";
        return html.replaceAll("<[^>]+>", "").replace("&lt;", "<").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&").trim();
    }
}
