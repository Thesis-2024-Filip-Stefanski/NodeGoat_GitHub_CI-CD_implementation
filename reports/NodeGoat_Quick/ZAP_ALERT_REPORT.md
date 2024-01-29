# NodeGoat scann report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 4 |
| Low | 5 |
| Informational | 0 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| CSP: Wildcard Directive | Medium | 1 |
| Content Security Policy (CSP) Header Not Set | Medium | 6 |
| Missing Anti-clickjacking Header | Medium | 6 |
| Vulnerable JS Library | Medium | 2 |
| Cookie without SameSite Attribute | Low | 3 |
| Cross-Domain JavaScript Source File Inclusion | Low | 6 |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 16 |
| Timestamp Disclosure - Unix | Low | 1 |
| X-Content-Type-Options Header Missing | Low | 14 |




## Alert Detail



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

Instances: 1

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

Instances: 3

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
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
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
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
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
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/tutorial
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
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/login
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://nodegoat_github_ci-cd_implementation_web_1:4000/signup
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: 14

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx ](http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3


