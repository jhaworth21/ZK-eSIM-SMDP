# import urllib.request as req
import treq

# contents = req.urlopen('143.167.129.60:8080').read()
# print(contents)
route = '/gsma/rsp2/es9plus/initiateAuthentication'
req = treq.get(f'http://143.167.129.60:8080/')
req.addCallback(lambda r: print("response", r.decode()))
