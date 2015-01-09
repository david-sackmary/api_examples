#!/usr/bin/env python2.7
#
# take hash from baseline and send to virustotal
# input - baseline scan from Halo
# output - results from VirusTotal.com
# David Sackmary <dsackmary@cloudpassage.com>
# Tim Spencer <tspencer@cloudpassage.com> (authored apiget.py, included here)
#
clientid = '173268a5'
clientsecret = '7444180d91b9b59000e429e57357a816' 
host = 'api.cloudpassage.com'

import urllib
import httplib
import base64
import json

# Get the access token used for the API calls.
connection = httplib.HTTPSConnection(host)
authstring = "Basic " + base64.b64encode(clientid + ":" + clientsecret)
header = {"Authorization": authstring}
params = urllib.urlencode({'grant_type': 'client_credentials'})
connection.request("POST", '/oauth/access_token', params, header)
response = connection.getresponse()
jsondata =  response.read().decode()
data = json.loads(jsondata)
key = data['access_token']

# Do the real request using the access token in the headers
tokenheader = {"Authorization": 'Bearer ' + key}
connection.request("GET", "/v1/servers", '', tokenheader)
response = connection.getresponse()
jsondata =  response.read().decode()
data = json.loads(jsondata)

# print out everything in a pretty way
#print json.dumps(data, sort_keys=True, indent=4)

# iterate through the list and print out the hostnames as an example of
# how to handle json data
#servers = data['servers']
#for server in servers:
#	print server['hostname']
#	print server['kernel_name']


# Get id for fim policy
#connection.request("GET", "/v1/fim_policies/", '', tokenheader)
#response = connection.getresponse()
#jsondata =  response.read().decode()
#data = json.loads(jsondata)
#print data

# print 'contents' for the given baseline
# note to self.. this baseline is hardcoded.  add logic here...
connection.request("GET", "/v1/fim_policies/be64cab06fdf0132a4ba3c764e10c221/baselines/cd20d5406fdf0132fe6f3c764e10c220/details", '', tokenheader)
response = connection.getresponse()
jsondata =  response.read().decode()
data = json.loads(jsondata)
#print json.dumps(data, sort_keys=True, indent=4)

#HELP - I can't parse objects or contents.  not yet sure why...
try:
contents = data['baseline']['details']['targets']#['objects']['contents']
for content in contents:
  print json.dumps(content, sort_keys=True, indent=4)
except:
  pass

#At this point, I have a file which can easily be grepped, and then pipe the hashes to virustotal.
#I am currently using a ruby program named 'uirusu' to interface with virustotal.  I will recode
#this in python for this example. (?)

connection.close()
