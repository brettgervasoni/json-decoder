# Burp Extension - JSON decoder
# Copyright : Michal Melewski <michal.melewski@gmail.com>

# Small content-type fix: Nicolas Gregoire
# Force JSON fix: Marcin 'Icewall' Noga
# Changes by Brett Gervasoni
#     * Included headers in decoder tab.
#     * Made force JSON detection more lenient, updated menuItems

import json

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
    False: "Turn on forced JSON detection",
    True:    "Turn off forced JSON detection"
}

# Content types
supportedContentTypes = [
    "application/json",
    "text/json",
    "text/x-json",
]

# Global Switch
_forceJSON = True

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName('JSON Decoder')
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)

        return

    def createNewInstance(self, controller, editable): 
        return JSONDecoderTab(self, controller, editable)

    def createMenuItems(self, IContextMenuInvocation):
        global _forceJSON
        menuItemList = ArrayList()
        menuItemList.add(JMenuItem(menuItems[_forceJSON], actionPerformed = self.onClick))

        return menuItemList

    def onClick(self, event):
        global _forceJSON
        _forceJSON = not _forceJSON

class JSONDecoderTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

        self._jsonMagicMark = ['{', '[', '[{']

        return

    def getTabCaption(self):
        return "JSON"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        global _forceJSON

        if isRequest:
            r = self._helpers.analyzeRequest(content)
        else:
            r = self._helpers.analyzeResponse(content)

        msg = content[r.getBodyOffset():].tostring().strip()

        if _forceJSON and len(msg) > 2 and msg[0] in self._jsonMagicMark:
            #print "Forcing JSON parsing and magic mark found: %s"%msg[0]
            return True

        for header in r.getHeaders():
            if header.lower().startswith("content-type:"):
                content_type = header.split(":")[1].lower()

                for allowedType in supportedContentTypes:
                    if content_type.find(allowedType) > 0:
                        return True

        return False

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

            try:
                boundary = min(
                    msg.index('{') if '{' in msg else len(msg),
                    msg.index('[') if '[' in msg else len(msg)
                    )
            except ValueError:
                print('Sure this is JSON?')
                return

            garbage = msg[:boundary]
            clean = msg[boundary:]

            try:
                #pretty_msg = garbage.strip() + '\n' + json.dumps(json.loads(clean), indent=4)
                pretty_msg = json.dumps(json.loads(clean), indent=4)
            except:
                print("problem parsing data in setMessage")
                pretty_msg = clean

            headers = ""
            for header in r.getHeaders():
                headers += header + "\n"

            pretty_msg = headers + pretty_msg

            self._txtInput.setText(pretty_msg)
            self._txtInput.setEditable(self._editable)

        self._currentMessage = content
        return

    def getMessage(self): 
        if self._txtInput.isTextModified():
            try:
                pre_data = self._txtInput.getText().tostring()

                boundary = min(pre_data.index('{'), pre_data.index('['))

                clean = pre_data[boundary:]
                data = json.dumps(json.loads(clean))
            except:
                data = self._helpers.bytesToString(self._txtInput.getText())

            #Reconstruct request/response
            r = self._helpers.analyzeRequest(self._currentMessage)

            return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
