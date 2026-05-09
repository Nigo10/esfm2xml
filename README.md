# esfm2xml
Tool for converting .esfm files to .xml and vice versa.

Vibecoded script to convert .esfm files to .xml and backwards. It can be used to modify the titles of PS4 trophies. 

You will need the game NPWR key to convert these files properly, these can be found in different sites (i.e. https://junaid2005.wordpress.com/ps4-npwr-list/)

Usage:
   Convert ESFM to XML: python esfm2xml.py esfm2xml TROP.ESFM NPWR00000_00 trop.xml
   
   Convert XML to ESFM: python esfm2xml.py xml2esfm trop.xml NPWR00000_00  out.esfm
   
   Automatic:  python esfm2xml.py auto TROP.ESFM/.xml NPWR00000_00 out.xml/esfm
