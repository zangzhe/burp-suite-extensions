# SuperPayload

# Java imports
from java.awt import Font
from javax.swing import JScrollPane, JTextPane
from javax.swing.text import SimpleAttributeSet

# burp imports
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import IBurpExtenderCallbacks
from burp import IExtensionStateListener
from burp import ITab

# python imports
import base64
import traceback

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IExtensionStateListener, ITab):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):   

        callbacks.registerExtensionStateListener(self)
        # keep a reference to our callbacks object
        self._callbacks = callbacks  
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("Super Payload")
        # register ourselves as a payload generator factory
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        # the Super Payload UI 
        self.scriptpane = JTextPane()
        self.scriptpane.setFont(Font('Monospaced', Font.PLAIN, 11))
        self.scrollpane = JScrollPane()
        self.scrollpane.setViewportView(self.scriptpane)
        callbacks.customizeUiComponent(self.getUiComponent())
        callbacks.addSuiteTab(self)
        self.scriptpane.requestFocus()

        # Compile the init script content
        self._code = compile('', '<string>', 'exec')
        self._script = ''

        script = callbacks.loadExtensionSetting('script')

        if script:
            script = base64.b64decode(script)

            self.scriptpane.document.insertString(
                self.scriptpane.document.length,
                script,
                SimpleAttributeSet())

            self._script = script
            self._code = compile(script, '<string>', 'exec')

        
        return

    def createNewInstance(self, attack):
    	return SuperGenerator(self, attack)

    def getGeneratorName(self):
    	return "SuperPayload"

    def extensionUnloaded(self):
        try:
            self.callbacks.saveExtensionSetting(
                'script', base64.b64encode(self._script))
        except Exception:
            traceback.print_exc(file=self.callbacks.getStderr())
        return

    def getTabCaption(self):
        return 'Super Payload Script'

    def getUiComponent(self):
        return self.scrollpane

    # Get the compiled code of user script (update or not)
    @property
    def script(self):
        end = self.scriptpane.document.length
        _script = self.scriptpane.document.getText(0, end)

        if _script == self._script:
            return self._code

        self._script = _script
        self._code = compile(_script, '<string>', 'exec')
        return self._code

# Get payloadList from user script,and form a generator
class SuperGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._attack = attack
        self._max_payload = 11
        self._current_paylaod = 1
        http_service = attack.getHttpService()
        payloadList = []
        try:
            exec(self._extender.script)
        except Exception:
            traceback.print_exc(file=self._extender._callbacks.getStderr())
        self._payloadList = payloadList
        self._currentPayloadIndex = 0
        if type(self._payloadList) != type([]):
            print 'Error: payload is not a list'
            self._payloadList = []
        #print self._payloadList
        return

    def getNextPayload(self, baseValue):
        payload = str(self._payloadList[self._currentPayloadIndex])
    	payloadBytes = self._extender._helpers.stringToBytes(payload)
    	self._currentPayloadIndex += 1
    	return payloadBytes

    def hasMorePayloads(self):
    	if self._currentPayloadIndex >= len(self._payloadList):
    		return False
    	return True

    def reset(self):
    	self._currentPayloadIndex = 0
    	return


