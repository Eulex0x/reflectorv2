package burp;

import java.util.ArrayList;
import java.util.regex.Pattern;

import static burp.Constants.*;

class Settings
{
    private String scopeOnly;
    private String aggressiveMode;
    private String checkContext;
    private String proxyListener;
    private IBurpExtenderCallbacks callbacks;
    private ArrayList<Object[]> contentTypes;
    private ArrayList<String> enabledCntentTypes;
    final private String FALSE_CONST = "false";
    final private String TRUE_CONST = "true";
    final private String DIVIDER_OBJECT = ":divider:";
    final private String DIVIDER_ARRAY = "|divider|";
    final  private String CONTENT_TYPES = "content types";


    public Settings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        scopeOnly = callbacks.loadExtensionSetting(SCOPE_ONLY);
        checkContext = callbacks.loadExtensionSetting(CHECK_CONTEXT);
        aggressiveMode = callbacks.loadExtensionSetting(AGGRESSIVE_MODE);
        // aggressive mode sends extra requests, so stay inside the Burp scope unless told otherwise
        proxyListener = callbacks.loadExtensionSetting(PROXY_LISTENER);
        if(proxyListener == null) {
            // Burp Community has no Scanner, so the proxy listener is the only way to get results there
            String[] version = callbacks.getBurpVersion();
            boolean community = version != null && version.length > 0 && version[0] != null
                    && version[0].toLowerCase().contains("community");
            proxyListener = community ? TRUE_CONST : FALSE_CONST;
        }
        if(scopeOnly == null)
            scopeOnly = TRUE_CONST;
        if(aggressiveMode == null)
            aggressiveMode = TRUE_CONST;
        if(checkContext == null)
            checkContext = FALSE_CONST;

        this.loadContentTypes();
    }

    public Boolean getScopeOnly() {
        return Boolean.valueOf(scopeOnly);
    }

    private String prepareArray() {
        String result = "";
        for(Object[] object : contentTypes ){
            result += String.valueOf(object[0]);
            result += DIVIDER_OBJECT;
            result += String.valueOf(object[1]);
            result += DIVIDER_ARRAY;
        }
        result.substring(0, DIVIDER_ARRAY.length());
        return result;
    }

    private ArrayList<Object[]> extractArray(String arrayPrepared) {
        ArrayList<Object[]> extractedArray = new ArrayList<Object[]>();
        String[] splitted = arrayPrepared.toLowerCase().split(Pattern.quote(DIVIDER_ARRAY));
        for(String objects : splitted){
            extractedArray.add(new Object[]{Boolean.valueOf(objects.split(Pattern.quote(DIVIDER_OBJECT))[0]), String.valueOf(objects.split(Pattern.quote(DIVIDER_OBJECT))[1])});
        }
        return extractedArray;
    }

    public Boolean getProxyListener() {
        return Boolean.valueOf(proxyListener);
    }

    public void setProxyListener(boolean proxyListener) {
        this.proxyListener = String.valueOf(proxyListener);
        callbacks.saveExtensionSetting(PROXY_LISTENER, this.proxyListener);
    }

    public Boolean getAggressiveMode() {
        return Boolean.valueOf(aggressiveMode);
    }

    public Boolean getCheckContext() {
        return Boolean.valueOf(checkContext);
    }

    public void setScopeOnly(boolean scopeOnly) {
        this.scopeOnly = String.valueOf(scopeOnly);
        callbacks.saveExtensionSetting(SCOPE_ONLY ,this.scopeOnly);
    }

    public void setAggressiveMode(boolean aggressiveMode) {
        this.aggressiveMode = String.valueOf(aggressiveMode);
        callbacks.saveExtensionSetting(AGGRESSIVE_MODE,this.aggressiveMode);
    }

    public void setCheckContext(boolean checkContext) {
        this.checkContext = String.valueOf(checkContext);
        callbacks.saveExtensionSetting(CHECK_CONTEXT ,this.checkContext);
    }

    public void saveContentTypes() {
        String contentTypesString = null;
        if(contentTypes.size()!=0)
            contentTypesString = prepareArray();
        callbacks.saveExtensionSetting(CONTENT_TYPES,contentTypesString);
        this.enabledCntentTypes = extractEnabledContentTypes();
    }

    private void loadContentTypes() {
        String preparedArray = this.callbacks.loadExtensionSetting(CONTENT_TYPES);
        if(preparedArray == null){
            contentTypes = new ArrayList<Object[]>();
            for (String type : new String[]{"text/html", "application/json", "application/javascript", "text/javascript", "application/xml", "text/xml"}) {
                contentTypes.add(new Object[]{Boolean.TRUE, type});
            }
        }
        else{
            contentTypes = this.extractArray(preparedArray);
        }
        this.enabledCntentTypes = extractEnabledContentTypes();
    }

    public ArrayList<String> getEnabledContentTypes() {
        return enabledCntentTypes;
    }

    public ArrayList<String> extractEnabledContentTypes(){
        ArrayList<String> enableContentTypes = new ArrayList();
        for(Object[] object : contentTypes){
            if(Boolean.valueOf((Boolean) object[0]))
                enableContentTypes.add(((String)object[1]));
        }
        return (enableContentTypes.size() == 0) ?  null : enableContentTypes;
    }
    public ArrayList<Object[]> getContentTypes() {
        return contentTypes;
    }

}