package burp;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import java.util.*;
import java.util.List;

import static burp.Constants.*;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab, IHttpListener, IExtensionStateListener
{
    public static final String PLUGIN_NAME = "Reflector v2 beta";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static final String DESCRIPTION_DETAILS = "Reflected parameters in ";
    private static final String XSS_POSSIBLE = "XSS (possible)";
    private static final String XSS_VULNERABLE= "XSS (vulnerable)";
    public static final String ALLOWED_CONTENT_TYPE = "Allowed Content-Type";
    public static final String DELETE = "Delete";
    public static final String ADD = "Add";
    private JPanel panel;
    private final String OPTIONS_NAME = "Scanner options";
    private final String AGGRESSIVE_MODE = "Aggressive mode";
    private final String SCOPE_ONLY = "Scope only";
    private final String CHECK_CONTEXT = "Check context";
    private JButton addButton;
    private JButton deleteButton;
    private JTextField contetTtypeTextField;
    private JTable table;
    private TableModel model;
    private JCheckBox scopeOnly;
    private JCheckBox aggressiveMode;
    private JCheckBox checkContext;
    private Settings settings;
    private JCheckBox proxyListener;
    private JTabbedPane tabs;
    private volatile ResultsPanel results;
    private final java.util.concurrent.atomic.AtomicInteger pendingProbes = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "reflector-v2-probe");
        t.setDaemon(true);
        return t;
    });
    
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName(PLUGIN_NAME);

        // settings do not need the UI, and the listeners below must never see them as null
        settings = new Settings(callbacks);
        callbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                panel = new JPanel();
                panel.setLayout(null);

                final JLabel label1 = new JLabel(OPTIONS_NAME);
                label1.setFont(new Font(label1.getFont().getName(), Font.BOLD, 16));
                label1.setBounds(58, 20, 130, 20);
                panel.add(label1);

                model = new BurpTableModel(settings);

                table=new JTable(model);
                TableColumnModel columnModel = table.getColumnModel();
                columnModel.getColumn(0).setPreferredWidth(65);
                columnModel.getColumn(1).setPreferredWidth(330);

                JScrollPane sp = new JScrollPane(table);
                table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                sp.setBounds(58, 200, 400, 250);
                sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                sp.setPreferredSize(new Dimension(400, 250));

                deleteButton = new JButton(DELETE);
                deleteButton.setBounds(58, 470, 130, 30  );
                panel.add(deleteButton);
                panel.add(sp);

                contetTtypeTextField = new JTextField();
                contetTtypeTextField.setBounds(200, 143, 160, 29);
                panel.add(contetTtypeTextField);
                contetTtypeTextField.setColumns(10);

                JLabel addLabel = new JLabel(ALLOWED_CONTENT_TYPE);
                addLabel.setBounds(58, 150, 140, 16);
                addLabel.setFont(new Font(label1.getFont().getName(), Font.PLAIN ,14));
                panel.add(addLabel);
                addButton = new JButton(ADD);
                addButton.setBounds(370, 143, 84, 30);
                panel.add(addButton);
                BurpExtender.OptionPanel optionPanel1 = placeOption(SCOPE_ONLY);
                JPanel option1 = optionPanel1.getPanel();
                scopeOnly = optionPanel1.getCheckBox();
                scopeOnly.setSelected(settings.getScopeOnly());
                option1.setBounds(58, 43, 130, 20);
                panel.add(option1);
                BurpExtender.OptionPanel optionPanel2 = placeOption(AGGRESSIVE_MODE);
                JPanel option2 = optionPanel2.getPanel();
                aggressiveMode = optionPanel2.getCheckBox();
                aggressiveMode.setSelected(settings.getAggressiveMode());
                option2.setBounds(58, 63, 135, 20);
                panel.add(option2);
                BurpExtender.OptionPanel optionPanel3 = placeOption(CHECK_CONTEXT);
                JPanel option3 = optionPanel3.getPanel();
                checkContext = optionPanel3.getCheckBox();
                checkContext.setSelected(settings.getCheckContext());
                option3.setBounds(58, 83, 130, 20);
                panel.add(option3);


                BurpExtender.OptionPanel optionPanel4 = placeOption(PROXY_LISTENER);
                JPanel option4 = optionPanel4.getPanel();
                proxyListener = optionPanel4.getCheckBox();
                proxyListener.setSelected(settings.getProxyListener());
                proxyListener.setToolTipText("Analyse Proxy traffic directly and list findings in the Results tab. Needed on Burp Community (no Scanner).");
                option4.setBounds(58, 103, 140, 20);
                panel.add(option4);

                initListener();

                results = new ResultsPanel(callbacks);
                tabs = new JTabbedPane();
                tabs.addTab("Results", results.component());
                tabs.addTab("Settings", panel);

                callbacks.customizeUiComponent(tabs);
                callbacks.addSuiteTab(BurpExtender.this);

                // the Scanner only exists in Burp Professional
                if (!isCommunity()) {
                    try {
                        callbacks.registerScannerCheck(BurpExtender.this);
                    } catch (Throwable t) {
                        callbacks.printError("Reflector v2: Scanner check unavailable, use the proxy listener: " + t);
                    }
                }
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    //listener  initializations
    private void initListener(){

        //add button
        addButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                String type = contetTtypeTextField.getText();
                Object[] rowData = {Boolean.TRUE, type};
                ((BurpTableModel)model).addRow(rowData);
            }
        });

        //delete button
        deleteButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                int i = table.getSelectedRow();
                if(i >= 0){
                    ((BurpTableModel)model).removeRow(i);
                }
            }
        });

        //table checkboxes
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int column = table.getSelectedColumn();
                int row = table.getSelectedRow();
                if(column == 0 && row >=0){
                    Boolean value = (Boolean)model.getValueAt(row,column);
                    value = !value;
                    model.setValueAt(value, row, column);
                }
            }
        });

        //checkbox option
        scopeOnly.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                settings.setScopeOnly(scopeOnly.isSelected());
            }
        });

        //checkbox option
        aggressiveMode.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setAggressiveMode(aggressiveMode.isSelected());
            }
        });

        //checkbox option
        proxyListener.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setProxyListener(proxyListener.isSelected());
            }
        });

        //checkbox option
        checkContext.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setCheckContext(checkContext.isSelected());
            }
        });

    }

    private OptionPanel placeOption(String optionName)
    {
        JPanel panelOption = new JPanel();
        BoxLayout boxlayout = new BoxLayout(panelOption, BoxLayout.X_AXIS);
        panelOption.setLayout(boxlayout);
        JCheckBox checkBox1 = new JCheckBox();
        checkBox1.setText("");
        panelOption.add(checkBox1);
        panelOption.add(Box.createRigidArea(new Dimension(5, 5)));
        final JLabel label1 = new JLabel();
        label1.setText(optionName);
        label1.setFont(new Font(label1.getFont().getName(), Font.PLAIN, 14));
        panelOption.add(label1);
        panelOption.setAlignmentX(Component.LEFT_ALIGNMENT);
        return new OptionPanel(panelOption, checkBox1);
    }

    @Override
    public String getTabCaption()
    {
        return PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return tabs;
    }

    private boolean isCommunity() {
        String[] version = callbacks.getBurpVersion();
        return version != null && version.length > 0 && version[0] != null && version[0].toLowerCase().contains("community");
    }

    @Override
    public void extensionUnloaded() {
        executor.shutdownNow();
    }

    // number of background probe jobs still running (used by the tests)
    int pendingProbes() {
        return pendingProbes.get();
    }

    private boolean contentTypeAllowed(byte[] response) {
        String contentType = "";
        for (String header: helpers.analyzeResponse(response).getHeaders()) {
            if (header.toLowerCase().startsWith("content-type:")) {
                contentType = header.toLowerCase().split(":", 2)[1].trim();
                break;
            }
        }
        // browsers sniff a response without a Content-Type, so test it too
        boolean allowed = contentType.isEmpty();
        for (String allowedContentType: settings.getEnabledContentTypes()) {
            if (contentType.contains(allowedContentType)) {
                allowed = true;
                break;
            }
        }
        return allowed;
    }

    private boolean isVulnerable(Map param) {
        if (!param.containsKey(VULNERABLE)) return false;
        return !settings.getCheckContext() || String.valueOf(param.get(VULNERABLE)).contains(CONTEXT_VULN_FLAG);
    }

    private void fill(Finding f, Map param) {
        f.allowed = Finding.plain(String.valueOf(param.containsKey(VULNERABLE) ? param.get(VULNERABLE) : ""));
        f.vulnerable = isVulnerable(param);
        f.pending = false;
    }

    // turn the analysis result into Results-tab rows
    private List<Finding> record(IHttpRequestResponse message, List<Map> reflections, boolean pending) {
        List<Finding> found = new ArrayList<>();
        URL url = helpers.analyzeRequest(message).getUrl();
        String method = helpers.analyzeRequest(message).getMethod();
        for (Map param : reflections) {
            Finding f = new Finding(method, url.getHost(), url.toString(), String.valueOf(param.get(NAME)),
                    String.valueOf(param.get(REFLECTED_IN)), ((List) param.get(MATCHES)).size(), message);
            if (pending) f.pending = true; else fill(f, param);
            found.add(f);
            if (results != null) results.add(f);
        }
        return found;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || toolFlag != IBurpExtenderCallbacks.TOOL_PROXY || !settings.getProxyListener()) {
            return;
        }
        try {
            byte[] request = messageInfo.getRequest();
            byte[] response = messageInfo.getResponse();
            if (request == null || response == null || settings.getEnabledContentTypes() == null) return;
            if (settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl())) return;
            if (!contentTypeAllowed(response)) return;

            // work on a copy: Burp may recycle messageInfo once this method returns
            final IHttpRequestResponse copy = new SimpleRR(request, response, messageInfo.getHttpService());
            final CheckReflection check = new CheckReflection(settings, helpers, copy, callbacks);
            final List<Map> reflections = check.detect();
            if (reflections.isEmpty()) return;

            StringBuilder names = new StringBuilder();
            for (Map param : reflections) {
                if (names.length() > 0) names.append(", ");
                names.append(param.get(NAME));
            }
            String old = messageInfo.getComment();
            messageInfo.setHighlight("orange");
            messageInfo.setComment((old == null || old.isEmpty() ? "" : old + " | ") + "Reflector v2: " + names);

            // probes send extra requests, so they must not block the browser: do them in the background
            boolean deep = settings.getAggressiveMode() || settings.getCheckContext();
            final List<Finding> found = record(copy, reflections, deep);
            if (deep) {
                pendingProbes.incrementAndGet();
                executor.submit(() -> {
                    try {
                        check.analyzeDeeper(reflections);
                        for (int i = 0; i < found.size(); i++) fill(found.get(i), reflections.get(i));
                    } catch (Throwable t) {
                        callbacks.printError("Reflector v2: analysis failed: " + t);
                        for (Finding f : found) f.pending = false;
                    } finally {
                        pendingProbes.decrementAndGet();
                        if (results != null) results.refresh();
                    }
                });
            }
        } catch (Exception e) {
            callbacks.printError("Reflector v2: " + e);
        }
    }



    final class OptionPanel {
        private final JPanel panel;
        private final JCheckBox checkBox;

        public OptionPanel(JPanel panel, JCheckBox checkbox) {
            this.panel = panel;
            this.checkBox = checkbox;
        }

        public JPanel getPanel() {
            return panel;
        }

        public JCheckBox getCheckBox() {
            return checkBox;
        }
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    //
    // implement IScannerCheck
    //

    private String buildIssueForReflection( Map param, boolean[] vulnerable)
    {
        String reflectedIn = "";
        reflectedIn+="<li>";
        reflectedIn+=param.get(NAME);
        reflectedIn+=" - reflected "+ String.valueOf(((List)param.get(MATCHES)).size())+" times ";
        if (param.containsKey(VULNERABLE))
        {
            reflectedIn += "and allow the following characters: "+ String.valueOf(param.get(VULNERABLE));
            if (settings.getCheckContext() && !String.valueOf(param.get(VULNERABLE)).contains(CONTEXT_VULN_FLAG))
                return reflectedIn+ "</li>" ;
            vulnerable[0] = true;
        }
        return reflectedIn+ "</li>" ;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) throws RuntimeException {
        // in proxy-listener mode the listener does the work, so the Scanner must not repeat it
        if (settings.getProxyListener())
            return null;
        if ( this.settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl()) )
            return null;
        if (baseRequestResponse.getResponse() == null || baseRequestResponse.getRequest() == null)
            return null;
        if (settings.getEnabledContentTypes() == null)
            return null;
        boolean isContentTypeAllowed = contentTypeAllowed(baseRequestResponse.getResponse());
        boolean[] vulnerable = {false};
        // start analyze request
        if ( isContentTypeAllowed )
        {
            //Initialize check reflections
            List<Map> reflections = new CheckReflection(settings, helpers, baseRequestResponse, callbacks).checkResponse();
            if (!reflections.isEmpty())
            {
                record(new SimpleRR(baseRequestResponse.getRequest(), baseRequestResponse.getResponse(), baseRequestResponse.getHttpService()), reflections, false);
                // report the issue
                String reflectedInBody = "";
                String reflectedInHeader = "";
                String reflectedInAll = "";
                List<int[]> matches = new ArrayList<>();
                List<Pair> pairs = new ArrayList<>();
                for(Map param: reflections) {

                    if(param.get(REFLECTED_IN).equals(BODY)){
                        reflectedInBody+=buildIssueForReflection(param, vulnerable);
                    }

                    if(param.get(REFLECTED_IN).equals(HEADERS)){
                        reflectedInHeader+=buildIssueForReflection(param, vulnerable);
                    }


                    if(param.get(REFLECTED_IN).equals(BOTH)){
                        reflectedInAll+=buildIssueForReflection(param, vulnerable);
                    }


                    for (Object pair : (ArrayList)param.get(MATCHES)) {
                        pairs.add(new Pair((int[]) pair));
                    }
                }
                String START = ":<br><ul>";
                String END = "</ul>";
                String reflectedSummary = "";
                if(!reflectedInHeader.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS + HEADERS+START+reflectedInHeader+END;
                if(!reflectedInBody.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS + BODY + START + reflectedInBody+END;
                if(!reflectedInAll.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS+BOTH+START+reflectedInAll+END;
                Collections.sort(pairs, new Comparator<Pair>() {
                    @Override
                    public int compare(Pair o1, Pair o2) {
                        if (o1.getStart() == o2.getStart())
                            return 0;
                        return o1.getStart() < o2.getStart() ? -1 : 1;
                    }
                });
                int[] tmpPair = null;
                for (Pair pair : pairs)
                {
                    if (tmpPair == null)
                        tmpPair = pair.getPair().clone();
                    else if (tmpPair[1] > pair.getPair()[0])
                        tmpPair[1] = Math.max(tmpPair[1], pair.getPair()[1]);
                    else {
                        matches.add(tmpPair);
                        tmpPair = pair.getPair().clone();
                    }
                }
                if (tmpPair != null) {
                    matches.add(tmpPair);
                }
                String issueName = vulnerable[0] ? XSS_VULNERABLE : XSS_POSSIBLE;
                List<IScanIssue> issues = new ArrayList<>();
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                        issueName,
                        reflectedSummary,
                        getSeverity(issueName)));
                return issues;
            } else return null;
        }
        else return null;
    }

    private String getSeverity(String issueName) {
        return XSS_VULNERABLE.equals(issueName) ? "High" : "Medium";
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
        {
            return -1;
        } else {
            return 0;
        }
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}
