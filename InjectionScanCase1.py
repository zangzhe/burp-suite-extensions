from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

from java.net import URL

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
	    print "MyScanCheck is running"
	    # use callbacks
	    self._callbacks = callbacks
	    # use helpers
	    self._helpers = callbacks.getHelpers()
	    # set extension's name
	    callbacks.setExtensionName('ScanCheck')
	    # register message editor tab factory
	    callbacks.registerScannerCheck(self)
	    self._passiveScanMatch = self._helpers.stringToBytes("titleop titleplayer")
	    self._activeScanInjectPayload = self._helpers.stringToBytes("payload")
	    self._activeScanMatch = self._helpers.stringToBytes("footerBar")
	    return

    def getMatches(self, response, match):
    	matches = []
    	start = 0
    	while start < len(response):
    		start = self._helpers.indexOf(response, match, True, start, len(response)-1)
    		if start == -1:
    			break
 			matches.append([start, start+len(match)])
			start += len(match)

    	return matches

	def doPassiveScan(self, baseRequestResponse):
		print "passiveScan running"
		matches = getMatches(baseRequestResponse.getResponse(), self._passiveScanMatch)
		if len(matches) != 0:
			issues = []
			issues.append(CustomScanIssue())
			return issues

		return None

	def doActiveScan(self, baseRequestResponse, insertionPoint):
		print "activeScan running"
		checkRequest = insertionPoint.buildRequest(self._activeScanInjectPayload)
		checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);
		matches = getMatches(checkRequestResponse.getResponse(), self._activeScanMatch)
		if len(matches) > 0:
			requestHighlights = []
			requestHighlights.append(insertionPoint.getPayloadOffsets(self._activeScanInjectPayload))
			
			issues = []
			issues.append(CustomScanIssue(baseRequestResponse.getHttpService,\
				self._helpers.analyzeRequest(baseRequestResponse).getUrl(),\
				self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches),\
				"Demo injection",\
				"Submitting string: " + self._helpers.bytesToString(self._activeScanInjectPayload)+" returned the string: " + self._helpers.bytesToString(self._activeScanMatch),\
				"High"))
			return issues
		else:
			return None

	def consolidateDuplicateIssue(existingIssue, newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1
		else:
			return 0


class CustomScanIssue(IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
	    return  self._name

	def getIssueType(self):
	    return 0;

	def getSeverity(self):
	    return self._severity;

	def getConfidence(self):
	    return "Certain"

	def getIssueBackground(self):
	    return None

	def getRemediationBackground(self):
	    return None
	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		return None

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
