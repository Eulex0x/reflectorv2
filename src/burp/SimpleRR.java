package burp;

/** Plain in-memory request/response pair, safe to keep after Burp recycles its own message object. */
class SimpleRR implements IHttpRequestResponse {
    private byte[] request;
    private byte[] response;
    private IHttpService service;
    private String comment;
    private String highlight;

    SimpleRR(byte[] request, byte[] response, IHttpService service) {
        this.request = request;
        this.response = response;
        this.service = service;
    }

    public byte[] getRequest() { return request; }
    public void setRequest(byte[] message) { this.request = message; }
    public byte[] getResponse() { return response; }
    public void setResponse(byte[] message) { this.response = message; }
    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }
    public String getHighlight() { return highlight; }
    public void setHighlight(String color) { this.highlight = color; }
    public IHttpService getHttpService() { return service; }
    public void setHttpService(IHttpService httpService) { this.service = httpService; }
}
