---
layout: post
title:  "Preventing SSL Pinning Bypass on iOS"
date:   2021-03-13
categories: swift iOS Apple
title: Preventing SSL Pinning Bypass on iOS
---

In this recent years, Attacker first step to reverse engineer the Mobile application is to bypass SSL/TLS Pinning, so to get start to prevent the app from bypassed i will start explaining from basics to advanced in several series of blogs.

--- 
---

[](#header-1)**Introduction to SSL Pinning**
---

SSL Pinning is a Mechanism used in Mobile Applications to Secure the Transmission between the Client and Server from **MITM** Attacks. SSL technique  is used by Applications to accept the  default to trusted certificates by Operating System which is stored in certificate store.

---

[](#header-2)**Why SSL Pinning ?**
---

---

When the application tries to communicate with the server or other applications , it doesen't validate which certificate is secured and trusted and which isn't. Let's take a Scenario to better understand the use of SSL Pinning.

---
**Scenario**
---

Attacker is able to generate a Self-Signed Certificates and install it to the Operating system trust's store to setup MITM attack to bypass SSL.

Impact :

    - Tamper the SSL Sessions and reverse engineer the app protocol or extracting the API Requests Acceess.

    - The root CAs which are trusted by the devices can also get compromised and can be used for generating certificates.

--- 

--- 
[](#header-3)**Prevent SSL Pinning Bypass**
---

There several Mechanism to prevent the SSL Pinning Bypass by means of **Chain Of Trust** : 

Certificate Pinning Knowing in advance the certificate of the server our application is communication with, we can hard-code  into the application itself and refuse communicating unless it is a perfect match.

---

--- 
[](#header-4)**How To Pin?**
---

This technqiue is to harden the security of Applications by adding extra layer of identity check performed by Application Itself.

Methods : 
     
- **Certificate**: There's drawback of using feature is Certificate have expire after certain period of time. When Implmenting Certificate Pinning in application , need to take care of Certificate while updating the Application.

- **Public Key**: Certificates Updated Regularly but the public key remains the same or you have the ability to keep it same. Therefore pinning the key makes the design more flexible, but a bit trickier to implement, as now we have to extract the key from the certificate, both at pinning time and at every connection.

        - Create a sha256 hashes and store them. It makes it easier to manage due to size and it allows shipping an application with a hash of a future certificate or key without exposing them ahead of time.

--- 

---
[](#header-5)**Certificate and Key Generation**
---

For explaination I  have used  **google.com** as an example and use in application. I found this very code very usefull on the internet, will link Github Repository for your reference.

- Create Certificate and sha256 Hash using the following command 
        
        - openssl s_client -connect www.google.com:443 -showcerts < /dev/null | openssl x509  -outform DER > google.der python -sBc "from __future__ import print_function;import hashlib;print(hashlib.sha256(open('google.der','rb').read()).digest(), end='')" | base64  KjLxfxajzmBH0fTH1/oujb6R5fqBiLxl0zrl2xyFT2E=

- Extract the Public key and Hash :
        
        - openssl x509 -pubkey -noout -in google.der -inform DER | openssl rsa -outform DER   -pubin -in /dev/stdin 2>/dev/null > googlekey.der python -sBc "from __future__ import print_function;import hashlib;print(hashlib.sha256(open('googlekey.der','rb').read()).digest(), end='')" | base64 4xVxzbEegwDBoyoGoJlKcwGM7hyquoFg4l+9um5oPOI=



--- 

---
[](#header-6)**Implementing in iOS**
---

We will implement the Key and Hash in the following code , the following code will try to check the connection working successfully.

    
            import Foundation
            import Security

    class URLSessionPinningDelegate: NSObject, URLSessionDelegate {

    let pinnedCertificateHash = "KjLxfxajzmBH0fTH1/oujb6R5fqBiLxl0zrl2xyFT2E="
    let pinnedPublicKeyHash = "4xVxzbEegwDBoyoGoJlKcwGM7hyquoFg4l+9um5oPOI="

    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(bytes: rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))

        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }


        return Data(hash).base64EncodedString()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Swift.Void) {

        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secresult)

                if(errSecSuccess == status) {
                    print(SecTrustGetCertificateCount(serverTrust))
                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {

                        // Certificate pinning, uncomment to use this instead of public key pinning

                //let serverCertificateData:NSData = SecCertificateCopyData(serverCertificate)
                    let certHash = sha256(data: serverCertificateData as Data)
                        if (certHash == pinnedCertificateHash) {
                            // Success! This is our server
                            completionHandler(.useCredential, URLCredential(trust:serverTrust))
                            return
                        }

                        / Public key pinning
                        let serverPublicKey = SecCertificateCopyPublicKey(serverCertificate)
                        let serverPublicKeyData:NSData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
                        let keyHash = sha256(data: serverPublicKeyData as Data)
                        if (keyHash == pinnedPublicKeyHash) {
                            // Success! This is our server
                            completionHandler(.useCredential, URLCredential(trust:serverTrust))
                            return
                        }

                    }
                }
            }
        }

        // Pinning failed
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}


- Create **URLSession** to validate the connection verified.


                if let url = NSURL(string: "https://www.google.com/") {

            let session = URLSession(
                configuration: URLSessionConfiguration.ephemeral,
                delegate: URLSessionPinningDelegate(),
                delegateQueue: nil)

            let task = session.dataTask(with: url as URL, completionHandler: { (data, response, error) -> Void in
                if error != nil {
                    print("error: \(error!.localizedDescription))")
                } else if data != nil {
                    if let str = NSString(data: data!, encoding: String.Encoding.utf8.rawValue) {
                        print("Received data:\n\(str)")
                    }
                    else {
                        print("Unable to convert data to text")
                    }
                }
            })
            
            task.resume()
        }
        else {
            print("Unable to create NSURL")
        }

--- 

---
[](#header-7)**Conclusion**

---

 It is much safer to rely on additional layer of protection since we have the luxury to pin the exact certificate or the public key we are expecting on the other side. We’ve learned how to extract a server key as well as how to implement the pinning on iOS. Stay tuned, in our next tutorial we will cover the methods to implement certificate pinning on Android.

---
---
[](#header-7)**References**

---
 
 1. [https://github.com/bugsee/examples-ios-certificate-pinning](https://github.com/bugsee/examples-ios-certificate-pinning).

 2. [https://appinventiv.com/blog/ssl-pinning-in-ios-app/](https://appinventiv.com/blog/ssl-pinning-in-ios-app/)


        








