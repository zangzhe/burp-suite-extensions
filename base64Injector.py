from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IParameter
from burp import ITab
from javax import swing
import string

class BurpExtender(IBurpExtender, IScannerInsertionPointProvider, ITab):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        self._textKey = ""
        self._base64Key = ""
        # set our extension name
        callbacks.setExtensionName("Serialized input scan insertion point")
        
        self._jPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Key of base64 value:"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._textKeyField = swing.JTextField('',30)
        boxHorizontal.add(self._textKeyField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Key in base64 value (injection point)"))
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self._base64KeyField = swing.JTextField('',30)
        boxHorizontal.add(self._base64KeyField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        submitQueryButton = swing.JButton('Submit Keys',actionPerformed=self.runSubmit)
        boxHorizontal.add(submitQueryButton)
        boxVertical.add(boxHorizontal)

        self._jPanel.add(boxVertical)
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(self)
        
        return
        
    def runSubmit(self, button):
        self._textKey = self._textKeyField.text
        self._base64Key = self._base64KeyField.text

    # implement ITab
    
    def getTabCaption(self):
    
        return "base64Injection"
    
    def getUiComponent(self):
    
        return self._jPanel
    # 
    # implement IScannerInsertionPointProvider
    #
    
    def getInsertionPoints(self, baseRequestResponse):
        if self._textKey == "" or self._base64Key == "":
            self._textKey = "data"
            self._base64Key = "input"

        #print self._textKey
        #print self._base64Key
        # retrieve the data parameter
        dataParameter = self._helpers.getRequestParameter(baseRequestResponse.getRequest(), self._textKey)
        if (dataParameter is None):
            return None
        
        else:
            # if the parameter is present, add a single custom insertion point for it
            return [ InsertionPoint(self._helpers, baseRequestResponse.getRequest(), dataParameter.getValue()) ]
        
# 
# class implementing IScannerInsertionPoint
#

class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, baseRequest, dataParameter):
        self._helpers = helpers
        self._baseRequest = baseRequest
        
        # URL- and base64-decode the data
        dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameter)))
        tmp_str = self._base64Key + "="
        # parse the location of the input string within the decoded data
        start = string.find(dataParameter, tmp_str) + len(tmp_str)
        self._insertionPointPrefix = dataParameter[:start]
        end = string.find(dataParameter, "&", start)
        if (end == -1):
            end = dataParameter.length()
        self._baseValue = dataParameter[start:end]
        self._insertionPointSuffix = dataParameter[end:]
        return
        
    # 
    # implement IScannerInsertionPoint
    #
    
    def getInsertionPointName(self):
        return "Base64-wrapped injection point"

    def getBaseValue(self):
        return self._baseValue

    def buildRequest(self, payload):
        # build the raw data using the specified payload
        input = self._insertionPointPrefix + self._helpers.bytesToString(payload) + self._insertionPointSuffix;
        
        # Base64- and URL-encode the data
        input = self._helpers.urlEncode(self._helpers.base64Encode(input));
        
        # update the request with the new parameter value
        return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter("data", input, IParameter.PARAM_BODY))

    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED
            