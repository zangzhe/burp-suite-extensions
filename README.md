burp-suite-extensions
=====================
## Requirements
```
Burp Suite Professional v1.6 Beta
jython-standalone-2.7-b2
```

## JSON Beautifier
### Description
```
Extention adds a MessageEditorTab to Burp's Messaage details panel, which \
shows the JSON data in a friendly format. 
```
### Installation
``` 
1. Confirm the jython standalone jar module is loaded, in \
Burp Suite - Extender - Options - Python Environment
2. Load the 'JSONBeautifier.py' in Burp Suite - Extensions as Python type.
```

## Super Payload
### Description
```
Extention adds a 'Super Payload Script' tab to Burp and a 'SuperPayload' \
generator in Burp Intruder module. User can write python script to define \
a list named 'payloadList' in the tab, and the generator will use the list\
as payload in Intruder.
```
### Installation
``` 
1. Confirm the jython standalone jar module is loaded, in \
Burp Suite - Extender - Options - Python Environment
2. Load the 'SuperPayload.py' in Burp Suite - Extensions as Python type.
```

## Base64 Injector
### Description
```
Extention adds a 'Base64 injector' tab to Burp, you can set parameters in the \
tab and generate scanner insertion point. This extension can help you run burp \
security cases on the parameters base64-encoded. 
```
### Installation
``` 
1. Confirm the jython standalone jar module is loaded, in \
Burp Suite - Extender - Options - Python Environment
2. Load the 'Base64Injector.py' in Burp Suite - Extensions as Python type.
```