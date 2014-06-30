# Burp Extension - JSON Beautifier

# python imports
import json

# burp imports
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IContextMenuFactory

# Java imports
from javax.swing import JMenuItem
from java.util import List, ArrayList

# Menu items
menuItems = {
  False: "Turn JSON active detection on",
  True:  "Turn JSON active detection off"
}

# Global Switch
_forceJSON = False

# use IBurpExtender for the callback register and helpers functions
# use IMessageEditorTabFactory for creating message editor tab
# use IContextMenuFactory for creating menu item
class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
  # the implement of IBurpExtender's method
  def registerExtenderCallbacks(self, callbacks):
    print "JSON  Beautifier"
    # use callbacks
    self._callbacks = callbacks
    # use helpers
    self._helpers = callbacks.getHelpers()

    # set extension's name
    callbacks.setExtensionName('JSON Beautifier')
    # register message editor tab factory
    callbacks.registerMessageEditorTabFactory(self)
    # register menu item factory
    callbacks.registerContextMenuFactory(self)
    
    return
  
  # the implement of message editor tab factory's method, will be invoked 
  # when see message details 
  def createNewInstance(self, controller, editable):
    ## create tab use the user's class 
    return JSONBeautifierTab(self, controller, editable)

  # the implement of menu item factory's method, will be called when
  # invoke the menu of burp
  def createMenuItems(self, IContextMenuInvocation):
    global _forceJSON
    # a list for menu items
    menuItemList = ArrayList()
    # add the items you need, use JMenuItem component, set the name and event 
    # method
    menuItemList.add(JMenuItem(menuItems[_forceJSON], actionPerformed = self.onClick))

    return menuItemList

  # the menu click event method
  def onClick(self, event):
    global _forceJSON
    _forceJSON = not _forceJSON
    
# the message editor tab class
class JSONBeautifierTab(IMessageEditorTab):
  def __init__(self, extender, controller, editable):
    # inherit some methods
    self._extender = extender
    self._helpers = extender._helpers
    self._editable = editable
    
    # we need a text editor under the tab
    self._txtInput = extender._callbacks.createTextEditor()
    self._txtInput.setEditable(editable)

    self._jsonMagicMark = ['{"', '["', '[{']
    
    return
  # set tab caption  
  def getTabCaption(self):
    return "JSON Beautifier"
    
  # put the text editor under the tab
  def getUiComponent(self):
    return self._txtInput .getComponent()
    
  # when invoke a message detail, the method will be used to judge enable
  def isEnabled(self, content, isRequest):
    global _forceJSON

    ## a request or a response ?
    if isRequest:
      r = self._helpers.analyzeRequest(content)
    else:
      r = self._helpers.analyzeResponse(content)

    msg = content[r.getBodyOffset():].tostring()

    ## use the decoder ?
    if not _forceJSON:
      return False

    ## have json data in body ?
    if len(msg) > 2 and msg[:2] in self._jsonMagicMark:
      print "Forcing JSON parsing and magic mark found: %s"%msg[:2]
      return True
    ## no body content, but the header content-type mark it as json
    for header in r.getHeaders():
      if header.lower().startswith("content-type:"):
        content_type = header.split(":")[1].lower()
        if content_type.find("application/json") > 0:
          return True
        else:
          return False

    return False
    
  # if isenabled, next will call this method, to process the req/res content
  # put needed content in the text editor
  def setMessage(self, content, isRequest):
    if content is None:
      self._txtInput.setText(None)
      self._txtInput.setEditable(False)
    else:
      if isRequest:
        r = self._helpers.analyzeRequest(content)
      else:
        r = self._helpers.analyzeResponse(content)
      
      msg = content[r.getBodyOffset():].tostring()
      
      garbage = msg[:msg.find("{")]
      clean = msg[msg.find("{"):]

      try:
        pretty_msg = garbage + json.dumps(json.loads(clean), indent=4)
      except:
        print "problem parsing data in setMessage"
        pretty_msg = garbage + clean

      self._txtInput.setText(pretty_msg)
      self._txtInput.setEditable(self._editable)
      
    self._currentMessage = content
    return
