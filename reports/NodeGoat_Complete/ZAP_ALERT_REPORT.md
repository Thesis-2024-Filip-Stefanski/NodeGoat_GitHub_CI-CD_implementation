# NodeGoat scann report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 2 |
| Medium | 5 |
| Low | 5 |
| Informational | 7 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Cross Site Scripting (DOM Based) | High | 4 |
| Cross Site Scripting (Reflected) | High | 3 |
| CSP: Wildcard Directive | Medium | 5 |
| Content Security Policy (CSP) Header Not Set | Medium | 6 |
| Directory Browsing | Medium | 1 |
| Missing Anti-clickjacking Header | Medium | 6 |
| Vulnerable JS Library | Medium | 2 |
| Cookie without SameSite Attribute | Low | 7 |
| Cross-Domain JavaScript Source File Inclusion | Low | 6 |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 16 |
| Timestamp Disclosure - Unix | Low | 1 |
| X-Content-Type-Options Header Missing | Low | 10 |
| Authentication Request Identified | Informational | 7 |
| Information Disclosure - Suspicious Comments | Informational | 3 |
| Loosely Scoped Cookie | Informational | 23 |
| Modern Web Application | Informational | 4 |
| Session Management Response Identified | Informational | 11 |
| User Agent Fuzzer | Informational | 32 |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 8 |




## Alert Detail



### [ Cross Site Scripting (DOM Based) ](https://www.zaproxy.org/docs/alerts/40026/)



##### High (High)

### Description

Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login%23jaVasCript:/*-/*%60/*%5C%60/*'/*%22/**/(/*%20*/oNcliCk=alert(5397&29%20&29//%250D%250A%250d%250a//%3C/stYle/%3C/titLe/%3C/teXtarEa/%3C/scRipt/--!%3E%5Cx3csVg/%3CsVg/oNloAd=alert(5397&29//%3E%5Cx3e
  * Method: `GET`
  * Parameter: ``
  * Attack: `#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e`
  * Evidence: ``
  * Other Info: `Tag name: button Att name:  Att id: `
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login%23javascript:alert(5397&29
  * Method: `GET`
  * Parameter: ``
  * Attack: `#javascript:alert(5397)`
  * Evidence: ``
  * Other Info: `Tag name: input Att name: userName Att id: userName`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login%23jaVasCript:/*-/*%60/*%5C%60/*'/*%22/**/(/*%20*/oNcliCk=alert(5397&29%20&29//%250D%250A%250d%250a//%3C/stYle/%3C/titLe/%3C/teXtarEa/%3C/scRipt/--!%3E%5Cx3csVg/%3CsVg/oNloAd=alert(5397&29//%3E%5Cx3e
  * Method: `POST`
  * Parameter: ``
  * Attack: `#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e`
  * Evidence: ``
  * Other Info: `Tag name: button Att name:  Att id: `
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login%23javascript:alert(5397&29
  * Method: `POST`
  * Parameter: ``
  * Attack: `#javascript:alert(5397)`
  * Evidence: ``
  * Other Info: `Tag name: input Att name: userName Att id: userName`

Instances: 4

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	

### Reference


* [ http://projects.webappsec.org/Cross-Site-Scripting ](http://projects.webappsec.org/Cross-Site-Scripting)
* [ https://cwe.mitre.org/data/definitions/79.html ](https://cwe.mitre.org/data/definitions/79.html)


#### CWE Id: [ 79 ](https://cwe.mitre.org/data/definitions/79.html)


#### WASC Id: 8

#### Source ID: 1

### [ Cross Site Scripting (Reflected) ](https://www.zaproxy.org/docs/alerts/40012/)



##### High (Medium)

### Description

Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: `"><scrIpt>alert(1);</scRipt>`
  * Evidence: `"><scrIpt>alert(1);</scRipt>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `email`
  * Attack: `"><scrIpt>alert(1);</scRipt>`
  * Evidence: `"><scrIpt>alert(1);</scRipt>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `userName`
  * Attack: `"><scrIpt>alert(1);</scRipt>`
  * Evidence: `"><scrIpt>alert(1);</scRipt>`
  * Other Info: ``

Instances: 3

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	

### Reference


* [ http://projects.webappsec.org/Cross-Site-Scripting ](http://projects.webappsec.org/Cross-Site-Scripting)
* [ https://cwe.mitre.org/data/definitions/79.html ](https://cwe.mitre.org/data/definitions/79.html)


#### CWE Id: [ 79 ](https://cwe.mitre.org/data/definitions/79.html)


#### WASC Id: 8

#### Source ID: 1

### [ CSP: Wildcard Directive ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.git/index
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: 
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/entries
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: 
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/wc.db
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: 
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/robots.txt
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: 
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/sitemap.xml
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: 
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`

Instances: 5

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ http://www.w3.org/TR/CSP2/ ](http://www.w3.org/TR/CSP2/)
* [ http://www.w3.org/TR/CSP/ ](http://www.w3.org/TR/CSP/)
* [ http://caniuse.com/#search=content+security+policy ](http://caniuse.com/#search=content+security+policy)
* [ http://content-security-policy.com/ ](http://content-security-policy.com/)
* [ https://github.com/shapesecurity/salvation ](https://github.com/shapesecurity/salvation)
* [ https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources ](https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 6

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ http://www.w3.org/TR/CSP/ ](http://www.w3.org/TR/CSP/)
* [ http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html ](http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html)
* [ http://www.html5rocks.com/en/tutorials/security/content-security-policy/ ](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
* [ http://caniuse.com/#feat=contentsecuritypolicy ](http://caniuse.com/#feat=contentsecuritypolicy)
* [ http://content-security-policy.com/ ](http://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Directory Browsing ](https://www.zaproxy.org/docs/alerts/0/)



##### Medium (Medium)

### Description

It is possible to view the directory listing.  Directory listing may reveal hidden scripts, include files, backup source files, etc. which can be accessed to read sensitive information.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial/
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial/`
  * Evidence: `parent directory`
  * Other Info: ``

Instances: 1

### Solution

Disable directory browsing.  If this is required, make sure the listed files does not induce risks.

### Reference


* [ http://httpd.apache.org/docs/mod/core.html#options ](http://httpd.apache.org/docs/mod/core.html#options)
* [ http://alamo.satlug.org/pipermail/satlug/2002-February/000053.html ](http://alamo.satlug.org/pipermail/satlug/2002-February/000053.html)


#### CWE Id: [ 548 ](https://cwe.mitre.org/data/definitions/548.html)


#### WASC Id: 48

#### Source ID: 1

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 6

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Vulnerable JS Library ](https://www.zaproxy.org/docs/alerts/10003/)



##### Medium (Medium)

### Description

The identified library bootstrap, version 3.0.0 is vulnerable.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `* Bootstrap v3.0.0`
  * Other Info: `CVE-2018-14041
CVE-2019-8331
CVE-2018-20677
CVE-2018-20676
CVE-2018-14042
CVE-2016-10735
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/*! jQuery v1.10.2`
  * Other Info: `CVE-2020-11023
CVE-2020-11022
CVE-2015-9251
CVE-2019-11358
`

Instances: 2

### Solution

Please upgrade to the latest version of bootstrap.

### Reference


* [ https://github.com/twbs/bootstrap/issues/28236 ](https://github.com/twbs/bootstrap/issues/28236)
* [ https://github.com/advisories/GHSA-pj7m-g53m-7638 ](https://github.com/advisories/GHSA-pj7m-g53m-7638)
* [ https://github.com/twbs/bootstrap/issues/20184 ](https://github.com/twbs/bootstrap/issues/20184)
* [ https://github.com/advisories/GHSA-ph58-4vrj-w6hr ](https://github.com/advisories/GHSA-ph58-4vrj-w6hr)
* [ https://github.com/twbs/bootstrap/issues/20631 ](https://github.com/twbs/bootstrap/issues/20631)
* [ https://github.com/advisories/GHSA-4p24-vmcr-4gqj ](https://github.com/advisories/GHSA-4p24-vmcr-4gqj)
* [ https://github.com/advisories/GHSA-9v3m-8fp8-mj99 ](https://github.com/advisories/GHSA-9v3m-8fp8-mj99)
* [ https://nvd.nist.gov/vuln/detail/CVE-2018-20676 ](https://nvd.nist.gov/vuln/detail/CVE-2018-20676)


#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### Source ID: 3

### [ Cookie without SameSite Attribute ](https://www.zaproxy.org/docs/alerts/10054/)



##### Low (Medium)

### Description

A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.git/index
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/entries
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/wc.db
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/robots.txt
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/sitemap.xml
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``

Instances: 7

### Solution

Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.

### Reference


* [ https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site ](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site)


#### CWE Id: [ 1275 ](https://cwe.mitre.org/data/definitions/1275.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``

Instances: 6

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) ](https://www.zaproxy.org/docs/alerts/10037/)



##### Low (Medium)

### Description

The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.git/index
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/entries
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/wc.db
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/images/owasplogo.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap/bootstrap.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/fonts/fontawesome-webfont.woff%3Fv=4.0.1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/sb-admin.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``

Instances: 16

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.

### Reference


* [ http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx ](http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx)
* [ http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html ](http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server - Unix

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap/bootstrap.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1428571435`
  * Other Info: `1428571435, which evaluates to: 2015-04-09 09:23:55`

Instances: 1

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/favicon.ico
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/images/owasplogo.png
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap/bootstrap.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/fonts/fontawesome-webfont.woff%3Fv=4.0.1
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/sb-admin.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: 10

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx ](http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=CUdcCRIjfjEwqhvY
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=CUdcCRIjtUxJkXToXCfBnrqT
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=svLzEGIMjrmqRvwn
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=svLzEGIMjrmqRvwneiNzhZJN
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=svLzEGIMmDgnUaxcLSCFZwstmmseZqexKUOPlQHr
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=uawGsCSb
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=uawGsCSboMBVQrGY
passwordParam=password
referer=http://nodegoat_github_ci-cd_implementation_web_1:4000/login
csrfToken=_csrf`

Instances: 7

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in the element starting with: "<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav", see evidence field for the suspicious comment/snippet.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `select`
  * Other Info: `The following pattern was used: \bSELECT\b and was detected 2 times, the first in the element starting with: "(function(e,t){var n,r,i=typeof t,o=e.location,a=e.document,s=a.documentElement,l=e.jQuery,u=e.$,c={},p=[],f="1.10.2",d=p.concat", see evidence field for the suspicious comment/snippet.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `username`
  * Other Info: `The following pattern was used: \bUSERNAME\b and was detected in the element starting with: "u[o]&&(delete u[o],c?delete n[l]:typeof n.removeAttribute!==i?n.removeAttribute(l):n[l]=null,p.push(o))}},_evalUrl:function(e){r", see evidence field for the suspicious comment/snippet.`

Instances: 3

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Loosely Scoped Cookie ](https://www.zaproxy.org/docs/alerts/90033/)



##### Informational (Low)

### Description

Cookies can be scoped by domain or path. This check is only concerned with domain scope.The domain scope applied to a cookie determines which domains can access it. For example, a cookie can be scoped strictly to a subdomain e.g. www.nottrusted.com, or loosely scoped to a parent domain e.g. nottrusted.com. In the latter case, any subdomain of nottrusted.com can access the cookie. Loosely scoped cookies are common in mega-applications like google.com and live.com. Cookies set from a subdomain like app.foo.bar are transmitted only to that domain by the browser. However, cookies scoped to a parent-level domain may be transmitted to the parent, or any subdomain of the parent.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AaIRaHhdZ7M387m5LxkZdbzH4YPsIo9NT.2CfFT60rF2tTTbV8X9iEwRQDLufcw9sdk72NS1Ipr%2FI
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3Aha1nIcudKZM2djYpP-1OGFNbCporpSVX.SW%2Bt8YuYA1KjjFxg0SJPayd19wzDkMVU7qFCrqL4o5k
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3A1SeWWYi-QISJ934bj-JX7ulnanHDryEF.0WuXzC0os0CL3QLj%2B65ikNAWvtv9v2FhIu1Oewd39b4
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3A44ABx0rATyjM0sJP1WHf8TjVKXnG-Ru3.zow0dCtKeAOyYLnZscGJCUqpfTVxyJPOO7gCmPn15No
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3A9HtSG-nGp1JwDygovcpBD-wr5bO9t2sJ.CKdihDp%2BM5lWlDlFEQ%2BW15ZHJrBgPtjb%2BX1EsGIArEs
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3A9n9Oz3vDoSyVtyZXmCyLu6R_OE2TkJn4.wu6GxA8W%2FddxJPs5GIAi4hxdJhjuWhdiBP%2F8LxHjdQQ
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AdijkE-DfmTs4cAZ-EWkH7ZM0W4Mqnqgt.PV0dtFasCh%2BbC%2BB%2B78M5S3Z%2BJS4Ci3S7mcijZkhYhWA
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AGJ3vyMAOcStyDYvRCsuDU76BrmugCyGA.4uLg3YdTXwCLPQPm2bPf4cWpRIOFt52hNJRP9CaD24c
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AgZAlZKzQZ5S36UJ9PBhoeAXZaUR-XGr-.StOffGuEOeTpEAqCmgOPtPxhqW1Ex6sUipCnNzl5OT8
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AH_4QGH6IQySaPsCMCx9C0VrkPvXgVH_P.6Py9Xdl5u0s9KYJYcS8pNUPFc%2Fl4c6hJ5lWTvbTJWzo
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AHruezQUY_YIK2lqSYMrhgDV057Hhw9WZ.Bs6pnDfnIpcjVMiRk3uOckl7H8R9DUNxBfRmtGxJIlc
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AHS5oMbGJwdpbxK3ir5auMRLnpsta0NmH.FYBX5OIErohwlUxKHUMMcp7WTxOgD11P%2F1UWrdD99JE
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3ANR0GrJeOiYqNVxrespj7KS1Emtkw32h3.JHUWqtskFK%2BSHOsCgFsrhOCZJHpIbPZd7aNh8jWJxu8
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3APqjaodQl7Dd3quW1n3C3xnN3HPBv1hVa.yQ6jEvlspXzAec6w3KhGUFhFXgLGpQHudngpoHSQVN0
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AqcAmp-Fs7r18xR5IY4pH3parzHKRCLOM.LBYXSt7GBnFSid7sC6wSFLYQ0JCyggOxFp%2Bbk5ZtXOI
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3ARwwfAvVmTIm7l32f4Sq3vaAkDtZsWZ6l.gVR5%2FFwmG6h54DyPRUivZiikXy0slO4JBDtst9iMhvY
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3ASvdGj81L88wrzSaESW8rFnNJ6UOiSUgN.6qtCjVUSN3xHrabII5AUA3abhFcFuW6y4I4ltmM6twM
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AUdE358sf9dKPNzRrtNZzZmStO7N3YfrB.uZdvjsLatk3Kd4%2F9bkntcC2FMAoH7A7jwIS3XECrNhc
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.git/index
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AwNKuU1rwrZJ3wIjSDo8as_14yprXnK0z.83052aD%2BIH3DXUsvd7KgmGrOP7S%2FsdWNBmFwHnkHCmo
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/entries
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AVwsISWya7EakCjynHMCEO8b0V8SucTEw.vzj%2FLMl9FFRHrvtBUhQDugIzfikvjA%2FUzskYDHv20XY
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/wc.db
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AXewx0-vMl3wPtHYfE5-tNyELOc56oBSU.9h8XtPzZKe2zRMKL9T6Y%2Bzc%2Brm1Gzcpw1TJpFb6r8d4
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3AC7jxaZiEpapb4Ms2VC25ZH3s_l-VGUSN.fLlu8bLHvG%2Fy4zJHG8ct4UDI%2FM2ZhHmViV%2FkfnbdTBs
`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `The origin domain used for comparison was: 
nodegoat_github_ci-cd_implementation_web_1
connect.sid=s%3Atkb10zOGE0vPHPzizXhDxSsJ31Ry5QS1.00fKCql6ky6pBSmoHZNUduYTdCkpxjDEXWEW6Jlvqng
`

Instances: 23

### Solution

Always scope cookies to a FQDN (Fully Qualified Domain Name).

### Reference


* [ https://tools.ietf.org/html/rfc6265#section-4.1 ](https://tools.ietf.org/html/rfc6265#section-4.1)
* [ https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html ](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html)
* [ http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies ](http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies)


#### CWE Id: [ 565 ](https://cwe.mitre.org/data/definitions/565.html)


#### WASC Id: 15

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" style="font-size: larger"><i class="fa fa-info-circle"></i></a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" style="font-size: larger"><i class="fa fa-info-circle"></i></a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A1 - Injection 
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-danger">Exploitability: EASY</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-warning">Detectability: AVERAGE</span>
            <span class="label label-danger">Technical Impact: SEVERE</span>
        </div>
    </div>
</div>


<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.
            </div>
        </div>
        <!--
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Real World Attack Incident Examples</h3>
            </div>
            <div class="panel-body">
                Screencast here ...
            </div>
        </div>
        -->
    </div>
</div>


<!-- accordions -->
<div class="panel-group" id="accordion">
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseOne">
                    <i class="fa fa-chevron-down"></i>A1 - 1 Server Side JS Injection
                </a>
            </h4>
        </div>
        <div id="collapseOne" class="panel-collapse collapse in">
            <div class="panel-body">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        When
                        <code>eval()</code>,
                        <code>setTimeout()</code>,
                        <code>setInterval()</code>,
                        <code>Function()</code>are used to process user provided inputs, it can be exploited by an attacker to inject and execute malicious JavaScript code on server.
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Web applications using the JavaScript
                            <code>eval()</code>function to parse the incoming data without any type of input validation are vulnerable to this attack. An attacker can inject arbitrary JavaScript code to be executed on the server. Similarly
                            <code>setTimeout()</code>, and
                            <code>setInterval()</code>functions can take code in string format as a first argument causing same issues as
                            <code>eval()</code>.
                        </p>
                        <p>This vulnerability can be very critical and damaging by allowing attacker to send various types of commands.</p>
                        <p>
                            <b>Denial of Service Attack:</b>
                        </p>
                        <iframe width="560" height="315" src="//www.youtube.com/embed/krOx9QWwcYw?rel=0" frameborder="0" allowfullscreen></iframe>
                        <p>
                            An effective denial-of-service attack can be executed simply by sending the commands below to
                            <code>eval()</code>function:
                        </p>


                        <pre>while(1)</pre>
                        <p>
                            This input will cause the target server's event loop to use 100% of its processor time and unable to process any other incoming requests until process is restarted.
                        </p>
                        <p>
                            An alternative DoS attack would be to simply exit or kill the running process:
                            <pre>process.exit()</pre> or <pre>process.kill(process.pid) </pre>
                        </p>
                        <p>
                            <b>File System Access</b>
                            <br/>
                        </p>
                        <iframe width="560" height="315" src="//www.youtube.com/embed/Mr-Jh9bjSLo?rel=0" frameborder="0" allowfullscreen></iframe>
                        <p>
                            Another potential goal of an attacker might be to read the contents of files from the server. For example, following two commands list the contents of the current directory and parent directory respectively:
                        </p>
                        <p>
                            <pre>res.end(require('fs').readdirSync('.').toString())</pre>
                            <pre>res.end(require('fs').readdirSync('..').toString()) </pre>
                        </p>
                        <p>
                            Once file names are obtained, an attacker can issue the command below to view the actual contents of a file:
                        </p>
                        <p>
                            <pre>res.end(require('fs').readFileSync(filename))</pre>
                        </p>
                        <p>
                            An attacker can further exploit this vulnerability by writing and executing harmful binary files using
                            <code>fs</code>and
                            <code>child_process</code>modules.
                        </p>
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        To prevent server-side js injection attacks:
                        <ul>
                            <li>Validate user inputs on server side before processing</li>
                            <li>Do not use
                                <code>eval()</code>function to parse user inputs. Avoid using other commands with similar effect, such as
                                <code>setTimeOut()</code>,
                                <code>setInterval()</code>, and
                                <code>Function()</code>.
                            </li>
                            <li>
                                For parsing JSON input, instead of using
                                <code>eval()</code>, use a safer alternative such as
                                <code>JSON.parse()</code>. For type conversions use type related
                                <code>parseXXX()</code>methods.
                            </li>
                            <li>Include
                                <code>"use strict"</code>at the beginning of a function, which enables <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions_and_function_scope/Strict_mode"> strict mode </a>within the enclosing function scope.</li>

                        </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>In
                            <code>routes/contributions.js</code>, the
                            <code>handleContributionsUpdate()</code>function insecurely uses
                            <code>eval()</code>to convert user supplied contribution amounts to integer.
                            <pre>
        // Insecure use of eval() to parse inputs
        var preTax = eval(req.body.preTax);
        var afterTax = eval(req.body.afterTax);
        var roth = eval(req.body.roth);
                            </pre> This makes application vulnerable to SSJS attack. It can fixed simply by using
                            <code>parseInt()</code>instead.
                            <pre>
        //Fix for A1 -1 SSJS Injection attacks - uses alternate method to eval
        var preTax = parseInt(req.body.preTax);
        var afterTax = parseInt(req.body.afterTax);
        var roth = parseInt(req.body.roth);
                            </pre>
                        </p>
                        <p>In addition, all functions begin with
                            <code>use strict</code>pragma.
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Further Reading</h3>
                    </div>
                    <div class="panel-body">
                        <ul>
                            <li><a target="_blank" href="https://media.blackhat.com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP.pdf">“ServerSide JavaScript Injection: Attacking NoSQL and Node.js"</a> a whitepaper by Bryan Sullivan.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /ssjs -->

    <!-- DB Injection -->
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseTwo">
                    <i class="fa fa-chevron-down"></i> A1 - 2 SQL and NoSQL Injection
                </a>
            </h4>
        </div>
        <div id="collapseTwo" class="panel-collapse">
            <div class="panel-body">


                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            SQL and NoSQL injections enable an attacker to inject code into the query that would be executed by the database. These flaws are introduced when software developers create dynamic database queries that include user supplied input.
                        </p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>Both SQL and NoSQL databases are vulnerable to injection attack. Here is an example of equivalent attack in both cases, where attacker manages to retrieve admin user's record without knowing password:</p>
                        <h5>1. SQL Injection</h5>
                        <p>Lets consider an example SQL statement used to authenticate the user with username and password</p>
                        <pre>SELECT * FROM accounts WHERE username = '$username' AND password = '$password'</pre>
                        <p>If this statement is not prepared or properly handled when constructed, an attacker may be able to supply
                            <code>admin' --</code>in the username field to access the admin user's account bypassing the condition that checks for the password. The resultant SQL query would looks like:</p>
                        <pre>SELECT * FROM accounts WHERE username = 'admin' -- AND password = ''</pre>
                        <br/>
                        <h5>2. NoSQL Injection</h5>
                        <p>The equivalent of above query for NoSQL MongoDB database is:</p>
                        <pre>db.accounts.find({username: username, password: password});</pre>
                        <p>While here we are no longer dealing with query language, an attacker can still achieve the same results as SQL injection by supplying JSON input object as below:</p>
                        <pre>
{
    "username": "admin",
    "password": {$gt: ""}
}
                        </pre>
                        <p>In MongoDB,
                            <code>$gt</code>selects those documents where the value of the field is greater than (i.e. >) the specified value. Thus above statement compares password in database with empty string for greatness, which returns
                            <code>true</code>.</p>
                        <p>The same results can be achieved using other comparison operator such as
                            <code>$ne</code>.</p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">SSJS Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Server-side JavaScript Injection (SSJS) is an attack where JavaScript code is injected and executed in a server component. MongoDB specifically, is vulnerable to this attack when queries are run without proper sanitization.
                        </p>

                        <h5>$where operator</h5>
                        <p>
                            MongoDB's
                            <code>$where</code> operator performs JavaScript expression evaluation on the MongoDB server. If the user is able to inject direct code into such queries then such an attack can take place
                        </p>

                        <p>
                            Lets consider an example query:
                        </p>
                        <pre> db.allocationsCollection.find({ $where: "this.userId == '" + parsedUserId + "' && " + "this.stocks > " + "'" + threshold + "'" }); </pre>

                        <p>
                            The code will match all documents which have a
                            <code>userId</code> field as specified by
                            <code>parsedUserId</code> and a
                            <code>stocks</code> field as specified by
                            <code>threshold</code>. The problem is that these parameters are not validated, filtered, or sanitised, and vulnerable to SSJS Injection.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        Here are some measures to prevent SQL / NoSQL injection attacks, or minimize impact if it happens:
                        <ul>
                            <li>Prepared Statements: For SQL calls, use prepared statements instead of building dynamic queries using string concatenation.</li>
                            <li>Input Validation: Validate inputs to detect malicious values. For NoSQL databases, also validate input types against expected types</li>
                            <li>Least Privilege: To minimize the potential damage of a successful injection attack, do not assign DBA or admin type access rights to your application accounts. Similarly minimize the privileges of the operating system account that the database process runs under.</li>
                        </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p><strong>Note: These vulnerabilities are not present when using an Atlas M0 cluster with NodeGoat.</strong></p>
                        <p>The Allocations page of the demo application is vulnerable to NoSQL Injection. For example, set the stocks threshold filter to:</p>
                        <pre>1'; return 1 == '1</pre>
                        <p>This will retrieve allocations for all the users in the database.</p>
                        <p>An attacker could also send the following input for the
                            <code>threshold</code> field in the request's query, which will create a valid JavaScript expression and satisfy the
                            <code> $where</code> query as well, resulting in a DoS attack on the MongoDB server:
                        </p>
                        <pre>http://localhost:4000/allocations/2?threshold=5';while(true){};' </pre>
                        <p>
                            You can also just drop the following into the Stocks Threshold input box:
                        </p>
                        <pre>';while(true){};'</pre>
                        <p>For these vulnerabilities, bare minimum fixes can be found in
                        <code>allocations.html</code> and
                        <code>allocations-dao.js</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /NoSQL Injection -->

    <!-- Log Injection -->
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseThree">
                    <i class="fa fa-chevron-down"></i> A1 - 3 Log Injection
                </a>
            </h4>
        </div>
        <div id="collapseThree" class="panel-collapse">
            <div class="panel-body">


                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Log injection vulnerabilities enable an attacker to forge and tamper with an application's logs.
                        </p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>An attacker may craft a malicious request that may deliberately fail, which the application will log, and when attacker's user input is unsanitized, the payload is sent as-is to the logging facility. Vulnerabilities may vary depending on the logging facility:</p>
                        <h5>1. Log Forging (CRLF) </h5>
                        <p>Lets consider an example where an application logs a failed attempt to login to the system. A very common example for this is as follows:
                        </p>
                        <pre>
var userName = req.body.userName;
console.log('Error: attempt to login with invalid user: ', userName);
                        </pre>
                        <p>When user input is unsanitized and the output mechanism is an ordinary terminal stdout facility then the application will be vulnerable to CRLF injection, where an attacker can create a malicious payload as follows:
                        <pre>
curl http://localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&password=Admin_123&_csrf='
                        </pre>
                        Where the <code>userName</code> parameter is encoding in the request the LF symbol which will result in a new line to begin. Resulting log output will look as follows:
                        <pre>
Error: attempt to login with invalid user:  vyva
Error: alex moldovan failed $1,000,000 transaction
                        </pre>
                        <br/>
                        <h5>2. Log Injection Escalation </h5>
                        <p>
                            An attacker may craft malicious input in hope of an escalated attack where the target isn't the logs themselves, but rather the actual logging system. For example, if an application has a back-office web app that manages viewing and tracking the logs, then an attacker may send an XSS payload into the log, which may not result in log forging on the log itself, but when viewed by a system administrator on the log viewing web app then it may compromise it and result in XSS injection that if the logs app is vulnerable.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">

                        As always when dealing with user input:
                        <ul>
                            <li>
                                Do not allow user input into logs
                            </li>
                            <li>
                                Encode to proper context, or sanitize user input
                            </li>
                        </ul>

                        Encoding example:
                        <pre>
// Step 1: Require a module that supports encoding
var ESAPI = require('node-esapi');
// - Step 2: Encode the user input that will be logged in the correct context
// following are a few examples:
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForHTML(userName));
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForJavaScript(userName));
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForURL(userName));
                        </pre>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>For the above Log Injection vulnerability, example and fix can be found at
                        <code>routes/session.js</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /Log Injection -->

</div>
<!-- end accordions -->

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" style="font-size: larger"><i class="fa fa-info-circle"></i></a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`

Instances: 4

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AaIRaHhdZ7M387m5LxkZdbzH4YPsIo9NT.2CfFT60rF2tTTbV8X9iEwRQDLufcw9sdk72NS1Ipr%2FI`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3Aha1nIcudKZM2djYpP-1OGFNbCporpSVX.SW%2Bt8YuYA1KjjFxg0SJPayd19wzDkMVU7qFCrqL4o5k`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AGJ3vyMAOcStyDYvRCsuDU76BrmugCyGA.4uLg3YdTXwCLPQPm2bPf4cWpRIOFt52hNJRP9CaD24c`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AqcAmp-Fs7r18xR5IY4pH3parzHKRCLOM.LBYXSt7GBnFSid7sC6wSFLYQ0JCyggOxFp%2Bbk5ZtXOI`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.git/index
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AwNKuU1rwrZJ3wIjSDo8as_14yprXnK0z.83052aD%2BIH3DXUsvd7KgmGrOP7S%2FsdWNBmFwHnkHCmo`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/entries
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AVwsISWya7EakCjynHMCEO8b0V8SucTEw.vzj%2FLMl9FFRHrvtBUhQDugIzfikvjA%2FUzskYDHv20XY`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/.svn/wc.db
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AXewx0-vMl3wPtHYfE5-tNyELOc56oBSU.9h8XtPzZKe2zRMKL9T6Y%2Bzc%2Brm1Gzcpw1TJpFb6r8d4`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/robots.txt
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AC7jxaZiEpapb4Ms2VC25ZH3s_l-VGUSN.fLlu8bLHvG%2Fy4zJHG8ct4UDI%2FM2ZhHmViV%2FkfnbdTBs`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/sitemap.xml
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3Atkb10zOGE0vPHPzizXhDxSsJ31Ry5QS1.00fKCql6ky6pBSmoHZNUduYTdCkpxjDEXWEW6Jlvqng`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AGJ3vyMAOcStyDYvRCsuDU76BrmugCyGA.4uLg3YdTXwCLPQPm2bPf4cWpRIOFt52hNJRP9CaD24c`
  * Other Info: `
cookie:connect.sid`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AqcAmp-Fs7r18xR5IY4pH3parzHKRCLOM.LBYXSt7GBnFSid7sC6wSFLYQ0JCyggOxFp%2Bbk5ZtXOI`
  * Other Info: `
cookie:connect.sid`

Instances: 11

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id)



#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/bootstrap
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/fonts
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/vendor/theme/font-awesome/fonts
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``

Instances: 32

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/login

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=CUdcCRIjfjEwqhvY

The user-controlled value was:
cudccrijfjewqhvy`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/login

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=CUdcCRIjtUxJkXToXCfBnrqT

The user-controlled value was:
cudccrijtuxjkxtoxcfbnrqt`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/login

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=svLzEGIMjrmqRvwn

The user-controlled value was:
svlzegimjrmqrvwn`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/login

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=svLzEGIMmDgnUaxcLSCFZwstmmseZqexKUOPlQHr

The user-controlled value was:
svlzegimmdgnuaxclscfzwstmmsezqexkuoplqhr`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/login

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=uawGsCSb

The user-controlled value was:
uawgscsb`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/login

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=uawGsCSboMBVQrGY

The user-controlled value was:
uawgscsbombvqrgy`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/signup

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=QuUjgWMG

The user-controlled value was:
quujgwmg`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://nodegoat_github_ci-cd_implementation_web_1:4000/signup

appears to include user input in: 

a(n) [input] tag [value] attribute 

The user input found was:
userName=QuUjgWMGrKOxycIM

The user-controlled value was:
quujgwmgrkoxycim`

Instances: 8

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute ](http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3


