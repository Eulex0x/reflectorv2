package burp;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.Constants.*;

public class CheckReflection {

    public static final int QUOTE_BYTE = 34;
    public static final int MIN_VALUE_LENGTH = 2;
    // pseudo parameter type for request headers that are tested for reflection
    public static final byte PARAM_HEADER = 100;
    private static final String[] HEADER_PARAMS = {"referer", "user-agent", "origin", "x-forwarded-host", "x-forwarded-for"};
    private final int bodyOffset;

    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private Settings settings;
    IBurpExtenderCallbacks callbacks;

    public CheckReflection(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = iHttpRequestResponse;
        byte[] response = iHttpRequestResponse.getResponse();
        this.bodyOffset = response == null ? 0 : helpers.analyzeResponse(response).getBodyOffset();
    }

    public List<Map> checkResponse() {
        List<Map> reflectedParameters = new ArrayList<>();
        byte[] response = iHttpRequestResponse.getResponse();
        byte[] request = iHttpRequestResponse.getRequest();
        if (response == null || request == null) {
            return reflectedParameters;
        }
        for (IParameter parameter : helpers.analyzeRequest(iHttpRequestResponse).getParameters()) {
            boolean quoted = true;
            if (parameter.getType() == IParameter.PARAM_JSON) {
                // numbers, booleans and null are not wrapped in quotes in JSON
                quoted = parameter.getValueStart() > 0 && request[parameter.getValueStart() - 1] == QUOTE_BYTE;
            }
            testValue(reflectedParameters, response, parameter.getName(), parameter.getValue(),
                    parameter.getType(), parameter.getValueStart(), parameter.getValueEnd(), quoted);
        }
        testHeaders(reflectedParameters, response, request);

        if (settings.getAggressiveMode() && !reflectedParameters.isEmpty()) {
            new Aggressive(settings, helpers, iHttpRequestResponse, callbacks, reflectedParameters).scanReflectedParameters();
        } else if (settings.getCheckContext() && !reflectedParameters.isEmpty()) {
            String body = helpers.bytesToString(response).substring(this.bodyOffset);
            for (Map parameter : reflectedParameters) {
                ArrayList<int[]> payloadIndexes = new ArrayList<>();
                for (int[] indexPair : (List<int[]>) parameter.get(MATCHES)) {
                    payloadIndexes.add(new int[]{indexPair[0] - this.bodyOffset, indexPair[1] - this.bodyOffset});
                }
                String symbols = new ContextAnalyzer(body.toLowerCase(), payloadIndexes).getIssuesForAllParameters();
                if (symbols.length() > 0) {
                    parameter.put(VULNERABLE, symbols);
                }
            }
        }
        return reflectedParameters;
    }

    private void testValue(List<Map> out, byte[] response, String name, String rawValue, byte type,
                           int valueStart, int valueEnd, boolean quoted) {
        byte[] decoded = helpers.urlDecode(helpers.stringToBytes(rawValue));
        if (decoded.length < MIN_VALUE_LENGTH) {
            return;
        }
        List<int[]> matches = getMatches(response, valueVariants(rawValue, decoded));
        if (matches.isEmpty()) {
            return;
        }
        Map description = new HashMap();
        description.put(NAME, name);
        description.put(VALUE, rawValue);
        description.put(TYPE, type);
        description.put(VALUE_START, valueStart);
        description.put(VALUE_END, valueEnd);
        description.put(QUOTED, quoted);
        description.put(MATCHES, matches);
        description.put(REFLECTED_IN, checkWhereReflectionPlaced(matches));
        out.add(description);
    }

    // request headers (Referer, User-Agent, ...) are not Burp parameters, so locate their values by hand
    private void testHeaders(List<Map> out, byte[] response, byte[] request) {
        String req = helpers.bytesToString(request);
        int pos = req.indexOf("\r\n");
        while (pos != -1) {
            int lineStart = pos + 2;
            int lineEnd = req.indexOf("\r\n", lineStart);
            if (lineEnd == -1 || lineEnd == lineStart) {
                break;
            }
            int colon = req.indexOf(':', lineStart);
            if (colon != -1 && colon < lineEnd) {
                String headerName = req.substring(lineStart, colon).trim().toLowerCase();
                for (String wanted : HEADER_PARAMS) {
                    if (wanted.equals(headerName)) {
                        int valueStart = colon + 1;
                        while (valueStart < lineEnd && req.charAt(valueStart) == ' ') {
                            valueStart++;
                        }
                        testValue(out, response, req.substring(lineStart, colon).trim(), req.substring(valueStart, lineEnd),
                                PARAM_HEADER, valueStart, lineEnd, true);
                        break;
                    }
                }
            }
            pos = lineEnd;
        }
    }

    // the decoded value plus the encodings an application commonly applies before reflecting it
    private List<byte[]> valueVariants(String rawValue, byte[] decoded) {
        String d = helpers.bytesToString(decoded);
        LinkedHashSet<String> variants = new LinkedHashSet<>();
        variants.add(d);
        variants.add(rawValue);
        variants.add(d.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
        variants.add(d.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;"));
        variants.add(d.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'").replace("/", "\\/"));
        variants.add(d.replace("\\", "\\\\").replace("\"", "\\u0022").replace("'", "\\u0027").replace("<", "\\u003c").replace(">", "\\u003e"));
        List<byte[]> result = new ArrayList<>();
        for (String v : variants) {
            if (v.length() >= MIN_VALUE_LENGTH) {
                result.add(helpers.stringToBytes(v));
            }
        }
        return result;
    }

    private String checkWhereReflectionPlaced(List<int[]> listOfMatches) {
        String reflectIn = "";
        for (int[] matches : listOfMatches) {
            if (matches[0] >= bodyOffset) {
                if (reflectIn.equals(HEADERS))
                    return BOTH;
                else
                    reflectIn = BODY;
            } else if (reflectIn.equals(BODY)) {
                return BOTH;
            } else {
                reflectIn = HEADERS;
            }
        }
        return reflectIn;
    }

    // find every occurrence of every variant, then drop the ones overlapping an earlier hit
    private List<int[]> getMatches(byte[] response, List<byte[]> variants) {
        List<int[]> all = new ArrayList<>();
        for (byte[] match : variants) {
            int start = 0;
            while (start < response.length) {
                start = helpers.indexOf(response, match, true, start, response.length);
                if (start == -1)
                    break;
                all.add(new int[]{start, start + match.length});
                start += match.length;
            }
        }
        all.sort((a, b) -> a[0] != b[0] ? Integer.compare(a[0], b[0]) : Integer.compare(b[1], a[1]));
        List<int[]> matches = new ArrayList<>();
        int lastEnd = -1;
        for (int[] m : all) {
            if (m[0] >= lastEnd) {
                matches.add(m);
                lastEnd = m[1];
            }
        }
        return matches;
    }
}

class Pair
{
    private int start;
    private int[] pair;
    public Pair(int[] pair)
    {
        this.start = pair[0];
        this.pair = pair;
    }
    public int getStart()
    {
        return start;
    }
    public int[] getPair()
    {
        return pair;
    }
}



class Aggressive
{
    // results of earlier probes, so browsing the same page again does not re-send the requests
    private static final Map<String, String> PROBE_CACHE = new ConcurrentHashMap<>();
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private List<Map> reflectedParameters;
    private IHttpRequestResponse baseRequestResponse;
    private static final String PAYLOAD_GREP = "p@y";
    private static final String PAYLOAD = "<\"'";
    private static final String PAYLOAD_JSON = "<\\\"'";
    private Pattern pattern;
    private Settings settings;

    Aggressive(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, List<Map> reflectedParameters) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.reflectedParameters = reflectedParameters;
        this.baseRequestResponse = baseRequestResponse;
        // encoded forms (&#X27;, %3C, <) can be long, so allow plenty of room between the markers
        this.pattern = Pattern.compile(PAYLOAD_GREP + "([_%&;\"'<#\\\\0-9a-zA-Z]{1,40}?)" + PAYLOAD_GREP);
        this.settings = settings;
    }

    public List<Map> scanReflectedParameters(){
        for (Map param : reflectedParameters)
        {
            if (HEADERS.equals(param.get(REFLECTED_IN))) {
                continue;
            }
            String key = cacheKey(param);
            String symbols = PROBE_CACHE.get(key);
            if (symbols == null) {
                symbols = checkResponse(prepareRequest(param));
                PROBE_CACHE.put(key, symbols);
            }
            if (!symbols.equals(""))
            {
                param.put(VULNERABLE, symbols);
            }
        }
        return reflectedParameters;
    }

    private String cacheKey(Map param) {
        IRequestInfo info = helpers.analyzeRequest(baseRequestResponse);
        return info.getMethod() + " " + info.getUrl().getProtocol() + "://" + info.getUrl().getHost() + ":"
                + info.getUrl().getPort() + info.getUrl().getPath() + " " + param.get(TYPE) + " " + param.get(NAME)
                + " " + settings.getCheckContext();
    }

    public static String prepareReflectedPayload(String value) {
        return value.replaceAll("[^<\"'\\\\]", "").replaceAll("(\\\\\"|\\\\')", "").replaceAll("[\\\\]", "");
    }

    private String checkResponse(String testRequest) {
        String  reflectedPayloadValue = "",
                symbols = "";
        int bodyOffset;
        try {

            IHttpRequestResponse responseObject = this.callbacks.makeHttpRequest(
                    this.baseRequestResponse.getHttpService(),
                    helpers.stringToBytes(testRequest)
            );
            if (responseObject == null || responseObject.getResponse() == null) {
                return "";
            }
            String response = helpers.bytesToString( responseObject.getResponse() );

            bodyOffset = helpers.analyzeResponse( responseObject.getResponse() ).getBodyOffset();

            Matcher matcher = this.pattern.matcher(response);
            ArrayList<int[]> payloadIndexes = new ArrayList<>();
            while (matcher.find()) {
                payloadIndexes.add( new int[] { matcher.start() - bodyOffset, matcher.end() - bodyOffset } );
            }

            if ( settings.getCheckContext() && bodyOffset < response.length()) {
                ContextAnalyzer contextAnalyzer = new ContextAnalyzer(response.substring(bodyOffset).toLowerCase(), payloadIndexes);
                symbols = contextAnalyzer.getIssuesForAllParameters();
            } else {
                for ( int[] indexPair: payloadIndexes ) {
                    reflectedPayloadValue = Aggressive.prepareReflectedPayload(response.substring(indexPair[0] + bodyOffset, indexPair[1] + bodyOffset));
                    if (reflectedPayloadValue.length() > 0) {
                        for (String str : reflectedPayloadValue.split("")) {
                            symbols += str + " ";
                        }
                    }
                    symbols = symbols + " || ";
                }

                if (!symbols.equals("")) {
                    symbols = symbols.substring(0, symbols.length() - 4).replaceAll("<", "&lt;").replaceAll("'", "&#39;").replaceAll("\"", "&quot;").replaceAll("\\|\\|", "<b>|</b>");
                }
            }
        } catch (Exception e) {
            callbacks.printError("Reflector v2: probe failed: " + e);
            return "";
        }
        return symbols;
    }

    private String prepareRequest(Map parameter) {
        boolean json = parameter.get(TYPE).equals(IParameter.PARAM_JSON);
        String inserted = PAYLOAD_GREP + (json ? PAYLOAD_JSON : PAYLOAD) + PAYLOAD_GREP;
        if (json && Boolean.FALSE.equals(parameter.get(QUOTED))) {
            // a bare JSON number/boolean has to become a string, otherwise the body stops being valid JSON
            inserted = "\"" + inserted + "\"";
        }
        String original = helpers.bytesToString(baseRequestResponse.getRequest());
        String tmpRequest = original.substring(0, (int) parameter.get(VALUE_START)) + inserted
                + original.substring((int) parameter.get(VALUE_END));

        int bodyOffset = helpers.analyzeRequest(baseRequestResponse).getBodyOffset();
        if ((int) parameter.get(VALUE_START) < bodyOffset) {
            return tmpRequest;
        }
        // value is in the body: recompute Content-Length from the new body size
        String headers = tmpRequest.substring(0, bodyOffset);
        Matcher cl = Pattern.compile("(?im)^content-length:[ \\t]*\\d+").matcher(headers);
        if (!cl.find()) {
            return tmpRequest;
        }
        int newLength = tmpRequest.length() - bodyOffset;
        return headers.substring(0, cl.start()) + "Content-Length: " + newLength + headers.substring(cl.end())
                + tmpRequest.substring(bodyOffset);
    }
}
