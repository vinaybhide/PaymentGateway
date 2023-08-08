<H3>Integrate SAP with Bank payment gateway - 
SOAP based Web Service to connect SAP with Bank's Payment Gateway API </H3>
<P>This web service provides interfaces to facilitate real time initiation of payment to customer's vendor's and employees</P>
<p>Banks typically provide payload posting functionality and another service for payment status. Along with providing interface to bank, this web service allows customers to overcome SAP's limitation related to digital signing and cryptography support (encryption & decryption) of payload</p>
<hr>
<li>Web service features & functionality</li>
<ol>
  <li>Interface available for posting- NEFT, RTGS and A2A (account to account) transfer</li>
  <li>Interface for status inquiry</li>
  <li>Digitally signs the payload using customers private key with RSA-SHA256 and embeds the certificate to the signature</li>
  <li>Encrypt the digitally signed payload using 32-byte symmetric key with AES/CBC/PKCS5 algorithm and is then encoded using Base 64 encoding</li>
  <li>The symmetric key along with signed payload is encrypted using banks SSL certificate (asymmetric Public Key) with RSA/ECB/PKCS1 algorithm and encoded using Base 64</li>
  <li>Entire API transaction is secured using oAuth 2.0 security</li>
  <li>Decryption of bank response and providing meaningful status to SAP</li>
</ol>
<li>Technlogy used</li>
<ol>
  <li>Entire interface is developed as SOAP Web Service</li>
  <li> Microsoft .Net standard framework</li>
  <li>C# and ASP.Net</li>
  <li>.Net framework's Certificate & Cryptography management</li>
</ol>
