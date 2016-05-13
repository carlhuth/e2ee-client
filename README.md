# End-to-End Encryption (E2EE) client

<a target="_blank" href="https://chrome.google.com/webstore/detail/e2ee-client/gijohbllljmpdlljfognplndkpfhllfe">
<img alt="Try it now" src="https://raw.github.com/GoogleChrome/chrome-app-samples/master/tryitnowbutton_small.png" title="Click here to install this app from the Chrome Web Store"></img>
</a>

E2EE client encrypts files and sends them to [E2EE server](https://github.com/xlab-si/e2ee-server). For cryptography it uses [Crypton](https://github.com/SpiderOak/crypton). However, Crypton was [slightly modified](https://github.com/xlab-si/e2ee-client/wiki/Speed-up-Javascript-crypto) to enable faster encryption/decryption of files.

# Usage

Files that are to be encrypted and stored on E2EE server can be dragged into E2EE client:

![drag file](https://github.com/xlab-si/e2ee-server/raw/master/pictures/drag.png)

Encrypted file is then listed in E2EE client: 

![encrypted file](https://github.com/xlab-si/e2ee-server/raw/master/pictures/file_encrypted.png)

Before the file is shared to another user, the trust has be established between the two users as shown below:

![establishing trust](https://github.com/xlab-si/e2ee-server/raw/master/pictures/trust1.png)

![establishing trust](https://github.com/xlab-si/e2ee-server/raw/master/pictures/trust2.png)


The file can be then shared to another user:

![sharing file](https://github.com/xlab-si/e2ee-server/raw/master/pictures/share1.png)

The user is now listed as being shared to:

![sharing file](https://github.com/xlab-si/e2ee-server/raw/master/pictures/share2.png)

The file is marked as being shared with a green icon:

![shared file](https://github.com/xlab-si/e2ee-server/raw/master/pictures/shared1.png)

The file is now available to the user to whom it was shared to - it is marked with a grey icon as shown:
![shared file](https://github.com/xlab-si/e2ee-server/raw/master/pictures/shared2.png)



# NOTICE #

This product includes software developed at "XLAB d.o.o, Slovenia". The development started as part of the "SPECS - Secure Provisioning of Cloud Services based on SLA Management" research project (EC FP7-ICT Grant, agreement 610795) and is continued in "WITDOM - empoWering prIvacy and securiTy in non-trusteD envirOnMents" research project (European Union’s Horizon 2020 research and innovation programme, agreement 64437).

* http://www.specs-project.eu/
* http://witdom.eu/
* http://www.xlab.si/



