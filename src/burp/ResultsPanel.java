package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

/** "Results" tab: one row per reflected parameter, click a row to see the request/response. */
class ResultsPanel implements IMessageEditorController {
    static final int MAX_ROWS = 2000;
    private static final String[] COLUMNS = {"Time", "Host", "Method", "URL", "Parameter", "In", "Hits", "Severity", "Allowed chars / context"};

    private final List<Finding> rows = new ArrayList<>();
    private final Map<String, Finding> byKey = new HashMap<>();
    private final JPanel root = new JPanel(new BorderLayout());
    private final JLabel counter = new JLabel("0 findings");
    private final AbstractTableModel model;
    private final JTable table;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private Finding current;

    ResultsPanel(IBurpExtenderCallbacks callbacks) {
        final SimpleDateFormat time = new SimpleDateFormat("HH:mm:ss");
        model = new AbstractTableModel() {
            public int getRowCount() { synchronized (rows) { return rows.size(); } }
            public int getColumnCount() { return COLUMNS.length; }
            public String getColumnName(int c) { return COLUMNS[c]; }
            public Object getValueAt(int r, int c) {
                Finding f;
                synchronized (rows) { if (r >= rows.size()) return ""; f = rows.get(r); }
                switch (c) {
                    case 0: return time.format(new Date(f.time));
                    case 1: return f.host;
                    case 2: return f.method;
                    case 3: return f.url;
                    case 4: return f.parameter;
                    case 5: return f.reflectedIn;
                    case 6: return f.count;
                    case 7: return f.pending ? "..." : f.severity();
                    default: return f.pending ? "testing..." : f.allowed;
                }
            }
        };
        table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) return;
            int r = table.convertRowIndexToModel(viewRow);
            Finding f;
            synchronized (rows) { f = r < rows.size() ? rows.get(r) : null; }
            show(f);
        });
        int[] widths = {60, 140, 55, 380, 100, 65, 40, 65, 300};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);

        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> clear());
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(clear);
        bar.add(counter);

        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);
        JTabbedPane viewers = new JTabbedPane();
        viewers.addTab("Request", requestViewer.getComponent());
        viewers.addTab("Response", responseViewer.getComponent());

        JPanel top = new JPanel(new BorderLayout());
        top.add(bar, BorderLayout.NORTH);
        top.add(new JScrollPane(table), BorderLayout.CENTER);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, viewers);
        split.setResizeWeight(0.5);
        root.add(split, BorderLayout.CENTER);
    }

    Component component() {
        return root;
    }

    /** add a finding, or refresh the row for the same method+URL+parameter. Safe to call from any thread. */
    void add(final Finding f) {
        synchronized (rows) {
            Finding old = byKey.get(f.key());
            if (old != null) {
                rows.remove(old);
            }
            byKey.put(f.key(), f);
            rows.add(f);
            while (rows.size() > MAX_ROWS) {
                Finding dropped = rows.remove(0);
                byKey.remove(dropped.key(), dropped);
            }
        }
        refresh();
    }

    /** a pending finding got its result */
    void refresh() {
        SwingUtilities.invokeLater(() -> {
            model.fireTableDataChanged();
            counter.setText(size() + " findings");
        });
    }

    int size() {
        synchronized (rows) { return rows.size(); }
    }

    List<Finding> snapshot() {
        synchronized (rows) { return new ArrayList<>(rows); }
    }

    void clear() {
        synchronized (rows) { rows.clear(); byKey.clear(); }
        current = null;
        refresh();
    }

    private void show(Finding f) {
        current = f;
        if (f == null) return;
        requestViewer.setMessage(f.message.getRequest(), true);
        responseViewer.setMessage(f.message.getResponse(), false);
    }

    public IHttpService getHttpService() { return current == null ? null : current.message.getHttpService(); }
    public byte[] getRequest() { return current == null ? null : current.message.getRequest(); }
    public byte[] getResponse() { return current == null ? null : current.message.getResponse(); }
}
