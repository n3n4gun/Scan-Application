# Scan-Application

Using library:
  - nmap3
  - networkscan
  - datetime
  - pythonping
  - re
  - socket
  - json
  - threading
  - PyQt5 (PySide6)
  
The main libraries which using in this application, which perform the main functional of application are:
  - nmap3
  - networkscan
  - pythonping
  - socket
  - threading

Nmap3
  This library is destin for implementation such types of scanning as:
    - TCP
    - UDP
    - SYN
    - Scan top ports
    - OS detection
    - IDLE scaning
    
Networkscan
  This library is destin for getting working ip addresses in the local network.
  
    self.NetworkFormat = '{}/{}'.format(self.IpAddr, self.NetMask)
    self.NetScan = networkscan.Networkscan(self.NetworkFormat)
...
