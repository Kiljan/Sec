import urllib.request
import json

from docxtpl Import DocxTemplate
import datetime

cve_to_check="CVE-2000-45088"

def main():
urlData = "https://services.nvd.nist.gov/rest/json/cues2.0?cveId=" + cve_to_check
jsonData = getResponse(urlData)

cve_id= ""
cve_description = ""
table_contents []
attackVector = ""
attackComplexity = ""
privilegesRequired = ""
userInteraction = ""
confidentialityImpact = ""
integrityImpact = ""
availabilityImpact = ""
baseScore = ""
baseSeverity = ""

for i in jsonData["vulnerabilities"]:
   cve_id = cve_to_check
   for j in i ["cve"]["references"]:
      table_contents.append("url": j["url"], "source": j["source"]})
   for k in i["cve"]["descriptions"]:
      if k["lang"] == "en":
         cve_description = k["value"]
   for l in i["cve"]["metrics"]["cvssMetricV31"]:
      attackVector = l["cussData"]["attackVector"]
      attackComplexity = l["cussData"]["attackComplexity"]
      privilegesRequired = l["cussData"]["privilegesRequired"]
      userInteraction = l["cvssData"]["userInteraction"]
      confidentialityImpact = l["cvssData"]["confident talttyImpact"]
      integrityImpact = l["cvssData"]["integrityImpact"]
      availabilityImpact = l["cvssData"]["availabilityImpact"]
      baseScore = l["cussData"]["baseScore"]
      baseSeverity = l["cussData"]["baseSeverity"]

template = DocxTemplate('cveTemplateUP.docx)

context = {
'title': cve 10,
'day': datetime.datetime.now().strftime("%d"),
'month': datetime.datetime.now().strftime("X"), 
'year': datetime.datetime.now().strftime("Y"), 
'table_contents': table_contents,
'cve_description': cve_description, 
'attackVector': attackVector,
'attackComplexity': attackComplexity,
'privilegesRequired': privilegesRequired, 
'userInteraction': userInteraction,
'confidentialityImpact': confidentialityImpact,
'integrityImpact': integrityImpact,
'availabilityImpact': availabilityImpact, 
'baseScore': baseScore,
'baseSeverity': baseSeverity
}

template.render(context) 
template.save("generated report.docx")

def getResponse(url):
   openUrl = urllib.request.urlopen(url)
   if(openUrl.getcode()==200):
      data = openUrl.read()
      jsonData = json.loads(data)
   else:
      print("Error receiving data", openUrl.getcode())
   return jsonData

if __name__ == '__main()__':
   main() 
