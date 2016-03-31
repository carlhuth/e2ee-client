# End-to-End Encryption (E2EE) client

<a target="_blank" href="https://chrome.google.com/webstore/detail/e2ee-client/gijohbllljmpdlljfognplndkpfhllfe">
<img alt="Try it now" src="https://raw.github.com/GoogleChrome/chrome-app-samples/master/tryitnowbutton_small.png" title="Click here to install this app from the Chrome Web Store"></img>
</a>

E2EE client encrypts files and sends them to [E2EE server](https://github.com/xlab-si/e2ee-server). For encryption/decryption it uses slightly modified [Crypton client](https://github.com/SpiderOak/crypton).

# Usage

Files that are to be encrypted and stored on E2EE server can be dragged into E2EE client:

.. image:: https://raw.github.com/xlab-si/e2ee-server/master/pictures/drag.png

Encrypted file is then listed in E2EE client: 

.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/file_encrypted.png

Before the file is shared to another user, the trust has be established between the two users as shown below:

.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/trust1.png

.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/trust2.png

The file can be then shared to another user:

.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/share1.png

The user is now listed as being shared to:

.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/share2.png

The file is marked as being shared with a green icon:

.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/shared1.png

The file is now available to the user to whom it was shared to - it is marked with a grey icon as shown:
.. image:: https://raw.githubusercontent.com/xlab-si/e2ee-server/master/pictures/shared2.png



# NOTICE #

This product includes software developed at "XLAB d.o.o, Slovenia". The development started as part of the "SPECS - Secure Provisioning of Cloud Services based on SLA Management" research project (EC FP7-ICT Grant, agreement 610795) and is continued in "WITDOM - empoWering prIvacy and securiTy in non-trusteD envirOnMents" research project (European Union’s Horizon 2020 research and innovation programme, agreement 64437).

* http://www.specs-project.eu/
* http://witdom.eu/
* http://www.xlab.si/



