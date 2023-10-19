# HTTP

An **HTTP message** (either a request or a response) contains multiple parts:

1. start line
2. headers
3. body

In a *request*, the start line indicates the **verb** used by the client, the **path of
the resource** it wants, and the **version of the protocol** it is going to use:
```http
GET /path/to/resource HTTP/1.1
```

After the start line, HTTP allows us to add metadata to the message through
**headers** which take the form of key-value pairs separated by a colon.
```http
GET /path/to/resource HTTP/1.1
Host: nba.com
Accept: */*
```

The HTTP specification considers multiple scenarios and has created headers to
deal with a plethora of situations. **Cache-Control** helps you scale better through
caching. **Stale-If-Error** makes your website available even if there’s a downtime,
this is one of those headers that should be understood extremely well, as it can
save a lot of troubles. **Accept** lets the client negotiate what kind of
**Content-Type** is best suited for the response.

When using custom headers, it is always preferred to prefix them with a key so
that they won’t conflict with other headers that might become standard in the
future. Historically, this worked until everyone started to use “non-standard”
**X** prefixes which, in turn, became the norm. The **X-Forwarded-For** and
**X-Forwarded-Proto** headers are examples of custom headers that are widely
used and understood by load balancers and proxies, even though they weren’t part
of the HTTP standard.

After the headers, a request might contain a **body**, which is separated from the
headers by a blank line.
```http
POST /path/to/resource HTTP/1.1
Host: nba.com
Accept: */*

Hey how are you?
```

Note that the *body is completely optional*, and, in most cases, is only used when
we want to send data to the server.

HTTP response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: private, max-age=3600

{"name": "Ravel", "birthplace": "Suli"}
```
The first information that the response advertises is the version of the
protocol it uses, and the status of this response. Headers follow suit and, if
required, a line break, followed by the body.

> **Cache-Control** helps you scale better through caching.
> **Stale-If-Error** makes your website available even if there’s a downtime,
> this is one of those headers that should be understood extremely well, as it
> can save a lot of troubles. Accept lets the client negotiate what kind of
> **Content-Type** is best suited for the response.
> **X-Forwarded-For** and **X-Forwarded-Proto** headers are examples of custom
> headers that are widely used and understood by load balancers and proxies.

## HSTS (HTTP Strict Transport Security)
A simple **Strict-Transport-Security: max-age=3600** will tell the browser that
for the next hour (3600 seconds) it should not interact with the applications
with insecure protocols.

When a user tries to access an application secured by HSTS through HTTP, the
browser will simply refuse to go ahead, automatically converting http:// URLs to
https://.

If you instead add the **hsts=on** parameter in your URL, the browser will
forcefully convert the link in the redirect to its https:// version.

You might be wondering what happens the first time a user visits your website,
as there is no HSTS policy defined beforehand. Attackers could potentially trick
the user to the http:// version of your website and perpetrate their attack
there, so there’s still room for problems. That’s a valid concern, as HSTS is a
**trust on first use mechanism**. It tries to make sure that once you’ve visited
a website, the browser knows that subsequent interactions must use HTTPS.

A way around this shortcoming would be to maintain a huge database of websites
that enforce HSTS, something that Chrome does through **hstspreload.org**. You
must set your policy then visit the website to check whether it’s eligible to be
added to the database.

By submitting your website to this list, you can tell browsers in advance that
your site uses HSTS so that even the first interaction between clients and your
server will be over a secure channel. This comes at a cost though, you really
need to commit to HSTS. It’s not an easy task for browser vendors to remove your
website from the list.
Be aware that inclusion in the preload list cannot easily be undone.

Domains can be removed, but it takes months for a change to reach users with a
Chrome update and we cannot make guarantees about other browsers. Don’t request
inclusion unless you’re sure that you can support HTTPS for your entire site and
all its subdomains for the long term.

Check for hsts preload: **https://hstspreload.org/**

## Expect-CT
The goal of **Expect-CT** is to inform the browser that it should perform
additional background checks to ensure the certificate is genuine. When a server
uses the Expect-CT header, it is requesting the client to verify that the
certificates being used are present in public **Certificate Transparency (CT)**
logs.

[*CT* is] an open framework for monitoring and auditing SSL certificates in
nearly real time. Specifically, Certificate Transparency makes it possible to
detect SSL certificates that have been mistakenly issued by a certificate
authority or maliciously acquired from an otherwise unimpeachable certificate
authority. It also makes it possible to identify certificate authorities that
have gone rogue and are maliciously issuing certificates.
_**certificate-transparency.org**_


```http
Expect-CT: max-age=3600, enforce, 
report-uri="https://ct.example.com/report"
```
- Enable CT verification for the current app for a period of one hour
(3600 seconds).
- _enforce_ this policy and prevent access to the app if a violation occurs.
- send a report to the given URL if a violation occurs.

## X-Frame-Options
**XFO** lets you decide whether your app can be embedded as an iframe on
external websites, preventing _clickjacking_ attack.

The supported values are:

- **DENY**: This web page cannot be embedded anywhere. This is the highest level
of protection as it doesn’t allow anyone to embed our content.
- **SAMEORIGIN**: Only pages from the same domain as the current one can embed
this page. This means that _example.com/embedder_ can load
_example.com/embedded_ so long as its policy is set to _SAMEORIGIN_. This is a
more relaxed policy that allows owners of a particular website to embed their
own pages across their application.
- **ALLOW-FROM <uri>**: Embedding is allowed from the specified URI. We could,
for example, let an external, authorized website embed our content by using
**ALLOW-FROM https://external.com**. This is generally used when you intend to
allow a third party to embed your content through an iframe.

```http
X-Frame-Options: DENY
```

XFO was considered the best way to prevent frame-based _clickjacking_ attacks
until another header came into play years later, the **Content Security Policy**.

## Content-Security-Policy
The **Content-Security-Policy** header, often abbreviated to CSP, provides a
next-generation utility belt for preventing a plethora of attacks, ranging from
_XSS (cross-site scripting)_ to _clickjacking_.
```http
Content-Security-Policy: default-src 'self'
```

Report-only mode

An interesting variation of CSP is the report-only mode: instead of using the
Content-Security-Policy header, you can first test the impact of CSP on your
website by telling the browser to simply report errors, without blocking script
execution. You can do this by using the Content-Security-Policy-Report-Only
header.
Reporting will allow you to understand what breaking changes could happen if you
roll out your CSP and then allow you to fix them accordingly. We can even
specify a report URL and the browser will send us a report. Here’s a full
example of a report-only policy:

```http
Content-Security-Policy: default-src 'self';
report-uri http://cspviolations.example.com/collector
```

Another example:

```http
Content-Security-Policy: default-src 'self';
script-src scripts.example.com; img-src *; 
media-src medias.example.com medias.legacy.example.com
```
This policy defines the following rules:

- executable scripts (e.g., JavaScript) can only be loaded from
_scripts.example.com_
- images may be loaded from any origin (_img-src: \*_)
- video or audio content can be loaded from two origins: _medias.example.com_
and medias.legacy.example.com

Note: Although superseded by CSP, the X-XSS-Protection header provides a
similar type of protection. Unsupported by Firefox, this header is used to
mitigate XSS attacks in older browsers that don’t fully support CSP.

## Feature-Policy
In July 2018, security researcher Scott Helme published a very interesting blog
post detailing a new security header in the making, **Feature-Policyi**.

```http
Feature-Policy: vibrate 'self'; push *; camera 'none'
```

- **vibrate 'self'**: this will allow the current page to use the vibration API and
any nested browsing contexts (iframes) on the same origin.
- **push * **: the current page and any iframe can use the push notification API.
- **camera 'none'**: access to the camera API is denied to the current page and
any nested context (iframes).

## X-Content-Type-Options
### MIME-sniffing
MIME-sniffing is the ability for a browser to auto-detect (and fix) the content
type of a resource it is downloading. Say for example, we ask the browser to
render an image at /awesome-picture.png, but the server sets the wrong type when
serving it to the browser (ie. Content-Type: text/plain), this would generally
result in the browser not being able to display the image properly.

In order to fix the issue, IE went to great lengths to implement a MIME-sniffing
capability. When downloading a resource, the browser would scan it and if it
detected that the resource’s content type is not the one advertised by the
server in the Content-Type header, it would ignore the type sent by the server
and interpret the resource according to the type detected by the browser.

Now, imagine hosting a website that allows users to upload their own images,
and imagine a user uploading a **/test.jpg** file that contains JavaScript code.
See where this is going? Once the file is uploaded, the site would include it in
its own HTML and, when the browser would try to render the document, it would
find the image the user just uploaded. As the browser downloads the image, it
would detect that it’s a script instead, and execute it on the victim’s browser.

To avoid this issue, we can set the X-Content-Type-Options: nosniff header that
completely disables MIME-sniffing. By doing so, we are telling the browser that
we’re fully aware that some file might have a mismatch in terms of type and
content, and the browser should not worry about it, we know what we’re doing, so
the browser shouldn’t try to guess things, potentially posing a security threat
to our users.

## Cross Origin Resource Sharing
On the browser HTTP requests can only be triggered across the same origin
through JavaScript. Simply put, an AJAX request from **example.com** can only
connect to **example.com**.

This is because your browser contains useful information for an attacker,
cookies, which are generally used to keep track of the user’s session.

There might be some cases, though, that require you to execute **cross-origin
AJAX requests**, and that is why browsers implement **Cross Origin Resource
Sharing (CORS)**, _a set of directives that allow you to execute
**cross-domain** requests_.

Notes:

- CORS is not a simple specification. There are quite a few scenarios to keep in
mind and you can easily get tangled in the nuances of features such as
**preflight requests**.
- Never expose APIs that change state via **GET**. An attacker can trigger those
requests without a preflight request, meaning there’s no protection at all.

Experience (CORS vs proxies):

> Out of experience, I found myself more comfortable with setting up proxies
> that can forward the request to the correct server, on the backend rather than
> using CORS. This means that your application running at example.com can set up
> a proxy at example.com/\_proxy/other.com, so that all requests falling under
> \_proxy/other.com/\* get proxied to other.com.

Related to CORS, the **X-Permitted-Cross-Domain-Policies** targets cross-domain
policies for Adobe products, namely Flash and Acrobat. I would simply suggest
adding an **X-Permitted-Cross-Domain-Policies: none** and ignore clients wanting to
make cross-domain requests with Flash.

## Referrer-Policy
At the beginning of our careers, we all probably made the same mistake, using
the Referer header to implement a security restriction on our website. If the
header contains a specific URL in a whitelist we define, we’re going to let
users through.

Ok, maybe that wasn’t every one of us, but I damn sure made the mistake of
trusting the Referer header to give us reliable information on the origin the
user comes from! The header was useful until we figured that sending this
information to sites could pose a potential threat to our users’ privacy because
it would specify which domains the users came from.
Born at the beginning of 2017 and currently supported by all major browsers, the
**Referrer-Policy** header can be used to mitigate these privacy concerns by
telling the browser that it should only mask the URL in the **Referrer** header or
omit it altogether.

Some of the most common values the **Referrer-Policy** can take are:

- **no-referrer**: the Referrer header will be entirely omitted
- **origin**: turns _https://example.com/private-page_ to _https://example.com/_
- **same-origin**: send the Referrer to same-site origins but omit it for anyone
else

It’s worth noting that there are many variations of the Referrer-Policy
(**strict-origin**, **no-referrer-when-downgrade**, etc.) but the ones I
mentioned above are going to cover most of your use cases.

### Origin and Referrer:
> The **Origin** header is very similar to Referrer, as it’s sent by the browser
> in cross-domain requests to make sure the caller is allowed to access a
> resource on a different domain. The Origin header is controlled by the
> browser, so there’s no way malicious users can tamper with it. You might be
> tempted to use it as a firewall for your web application. If the Origin is in
> our whitelist, it lets the request go through.
> One thing to consider is that other HTTP clients such as cURL can present
> their own origin. A simple _curl -H "Origin: example.com" api.example.com_
> will render all origin-based firewall rules inefficient. That is why you
> cannot rely on the Origin (or the Referrer, as we’ve just seen) to build a
> firewall to keep malicious clients away.

## Reporting API
In late 2018, Chrome rolled out a new feature to help web developers manage
browser reports of exceptions. Amongst the issues that can be managed with the
reporting API there are security ones, like CSP or feature-policy violations.

```http
Reporting-Endpoints:
main-endpoint="https://reports.example/main",
default="https://reports.example/default"
```
Read more: _https://developer.chrome.com/articles/reporting-api/_

The reporting API can be used to receive information regarding multiple aspects
of our users’ experience on our web application, such as:

- CSP and feature-policy violations
- risky code: the browser will sometimes intervene and block our code from
performing a specific action as we’ve seen with CSP and the **X-XSS-Protection**
headers
- deprecations: when our application uses an API that the vendor is planning to
deprecate
- crashes: when our application has caused the client to crash

If setting up a URL that can capture browser reports isn’t feasible, consider
using **report-uri.com**, a service that allows you to collect and analyze
browser reports with a single line of code.

## Securiity Headers Check
**https://securityheaders.com/** is an incredibly useful website that allows you
to verify that your web application has the correct security-related headers in
place.

# Cookies
Cookies are nothing more than a way to store data sent by the server and send it
along with future requests. The server sends a cookie, which contains small bits
of data, the browser stores it and sends it along with future requests to the
same server.

Cookies are generally used to store session IDs or access tokens, an attacker’s
holy grail. Once they are exposed or compromised, attackers can impersonate
users or escalate their privileges on your application. Securing cookies is one
of the most important aspects when implementing sessions on the web.

A server can send a cookie using the **Set-Cookie** header.
```http
HTTP/1.1 200 Ok
Set-Cookie: access_token=1234
```
servers can send multiple cookies at once
```http
HTTP/1.1 200 Ok
Set-Cookie: access_token=1234
Set-Cookie: user_id=10
```
and clients can do the same in their request.
```http
GET / HTTP/1.1
Host: example.com
Cookie: access_token=1234; user_id=10
```
In addition to the plain key and value, cookies can carry additional directives
that limit their time-to-live and scope.

### Expires
Specifies when a cookie should expire, so that browsers do not store and
transmit it indefinitely.
```http
HTTP/1.1 200 Ok
Set-Cookie: access_token=1234;
Expires=Fri, 24 Aug 2018 04:33:00 GMT
Set-Cookie: user_id=10;
Expires=Fri, 24 Aug 2019 04:33:00 GMT
```

### Max-Age
Similar to the Expires directive, Max-Age specifies the number of seconds until
the cookie should expire. A cookie that should last one hour would look like the
following:
```http
HTTP/1.1 200 Ok
Set-Cookie: access_token=1234;Max-Age=3600
```

### Domain
This directive defines which hosts the cookie should be sent to. Remember,
cookies generally contain sensitive data, so it’s important for browsers not to
leak them to untrusted hosts. A cookie with the directive
**Domain=trusted.example.com** will not be sent along with requests to any
domain other than **trusted.example.com**, not even the root domain,
**example.com**.
```http
HTTP/1.1 200 Ok
Set-Cookie: access_token=1234;Domain=trusted.example.com
```

### Path
**Path** is similar to the **Domain** directive but applies to the URL path
(**/some/path**). This directive prevents a cookie from being shared with
untrusted paths.
```http
HTTP/1.1 200 Ok
Set-Cookie: access_token=1234;Path=/trusted/path
```

### Session cookies
When a server sends a cookie without setting its **Expires** or **Max-Age**,
browsers treat it as a session cookie. Rather than guessing its time-to-live,
the browser deletes it when it shuts down.

### Persistent cookies
A persistent cookie, on the contrary, is stored on the client until the deadline
set by its **Expires** or **Max-Age** directives.

### Session restoring
It is worth noting that browsers might employ a mechanism known as session
restoring, where session cookies can be recovered after the client shuts down.
Browsers have implemented this kind of mechanism to conveniently let users
resume a session after a crash.

### Host-only
When a server does not include a **Domain** directive the cookie is to be
considered **host-only**, meaning that its validity is restricted to the current
domain only (and not its subdomains). This is a sort of default behavior from
browsers when they receive a cookie that does not have a Domain set.

## Supercookies

What if we were able to set a cookie on a _top-level domain (TLD)_ such as
**.com** or **.org**? That would be a huge security concern, for two reasons:

- **user privacy**: every website running on that specific TLD would be able to
track information about the user in shared storage
- **information leakage**: a server could mistakenly store a sensitive piece of
data in a cookie available to other sites

Luckily, **TLD-cookies**, otherwise known as **supercookies**, are disabled by
web browsers. If you try to set a supercookie, the browser will simply refuse to
do so.

permacookies (permanent cookies). zombiecookies (cookies that never die).

Companies love to make money out of ads, that’s no news. But when ISPs start to
aggressively track their customers in order to serve unwanted ads, well, that’s
a different story.

Another interesting example was Comcast, who used to include unwanted ads
through custom JavaScript code in web pages served through its network.

Needless to say, if all web traffic would be served through **HTTPS** we
wouldn’t have this problem as ISPs wouldn’t be able to decrypt and manipulate
traffic on-the-fly.

There are three very important directives (**Secure**, **HttpOnly**, and
**SameSite**) that should be understood before using cookies as they heavily
impact how cookies are stored and secured.

### Secure
Most _session hijacking_ attacks usually happen through a _man-in-the-middle_
who can listen to the unencrypted traffic between the client and server and
steal any information that’s been exchanged. If a cookie is exchanged via HTTP,
then it’s vulnerable to MITM attacks and session hijacking.

To overcome the issue, we can use HTTPS when issuing the cookie and add the
**Secure** flag to it. This instructs browsers to never send this cookie in
plain HTTP requests.

Marking sensitive cookies as **Secure** is an incredibly important aspect of
cookie security. _Even if you serve all of your traffic to HTTPS_, attackers
could find a way to set up a plain old HTTP page under your domain and redirect
users there. Unless your cookies are **Secure**, they will have access to a very
delicious meal.

### HttpOnly
By using this **HttpOnly** flag directive we can instruct the browser not to
share the cookie with JavaScript. The browser then removes the cookie from the
_window.cookie_ variable, making it impossible to access the cookie via JS.

The trick, in this case, is that the cookie is never exposed to the end-user,
and remains private between the browser and the server.

In 2003, researchers found an interesting vulnerability around the HttpOnly
flag, **Cross-Site Tracing (XST)**.

In a nutshell, browsers wouldn’t prevent access to **HttpOnly** cookies when
using the **TRACE** request method. While most browsers have now disabled this
method, my recommendation would be to disable **TRACE** at your webserver’s
level, returning the _405 Not allowed_ status code

### SameSite
Introduced by Google Chrome v51, this flag effectively eliminates **Cross-Site
Request Forgery (CSRF)** from the web, SameSite is a simple yet groundbreaking
innovation as previous solutions to CSRF attacks were either incomplete or too
much of a burden to site owners.

suppose that you are logged in on your banking website, which has a mechanism to
transfer money based on an HTML <form> and a few additional parameters like
destination account and amount. When the website receives a POST request with
those parameters and your session cookie, it will process the transfer. Now,
suppose a malicious third party website sets up an HTML form as such.

See where this is getting? If you click on the submit button, cleverly disguised
as an attractive prize, $1000 is going to be transferred from your account. This
is a cross-site request forgery, nothing more, nothing less.

Traditionally, there have been two ways to get rid of CSRF:

1. Origin and Referrer headers: The server could verify that these headers come
   from trusted sources (ie. https://bank.com). The downside to this approach is
   that, as we’ve seen in previous chapters, neither the Origin nor Referrer are
   very reliable and could be turned off by the client in order to protect the
   user’s privacy.
2. CSRF tokens: The server could include a signed token in the form and verify
   its validity once the form is submitted. This is a generally solid approach
   and it’s been the recommended best practice for years. The drawback of CSRF
   tokens is that they’re a technical burden for the backend, as you’d have to
   integrate token generation and validation in your web application: this might
   not seem like a complicated task, but a simpler solution would be more than
   welcome.

**SameSite** cookies aim to supersede the solutions mentioned above once and for
all. When you tag a cookie with this flag, you tell the browser not to include
the cookie in requests that were generated by different origins. When the
browser initiates a request to your server and a cookie is tagged as
**SameSite**, the browser will first check whether the origin of the request is
the same origin that issued the cookie. If it’s not, the browser will not
include the cookie in the request.

This ingenious flag has two main variants, **Lax** and **Strict**. Our example
uses the former variant, as it allows **top-level** navigation to a website to
include the cookie; when you tag a cookie as **SameSite=Strict** instead, the
browser will not send the cookie across any cross-origin request, including
top-level navigation: this means that if you click a link to a website that uses
strict cookies you won’t be logged in at all – an extremely high amount of
protection that, on the other hand, might surprise users. The Lax mode allows
these cookies to be sent across requests using safe methods (such as GET),
creating a very useful mix between security and user experience.

The last variant for this flag, None, can be used to opt-out of this feature
altogether. You might think that by not specifying the SameSite policy for a
cookie, browsers would treat it the same way they did for years while, in
reality, vendors are preparing to step up their security game. Chrome 80, set to
be released in Q1 2020, is going to apply a default SameSite=Lax attribute if a
cookie doesn’t have a value set for this flag. Firefox developers have already
stated they’d like to follow suit, so using SameSite=None will be the only way
to ask the browser to ignore its default SameSite policy. It’s worth noting
that, in order to push for the adoption of stricter security policies, browsers
will reject cookies opting out of SameSite unless they are declared Secure. To
quote Scott Helme, “CSRF is (really) dead”

## localStorage
Especially in the context of single-page applications (SPA), localStorage is
sometimes mentioned when discussing where to store sensitive tokens. The problem
with this approach, though, is that localStorage does not offer any kind of
protection against XSS attacks. If an attacker is able to execute a simple
localStorage.getItem('token') on a victim’s browser, it’s game over. HttpOnly
cookies easily overcome this issue.

# Approaches and Best Practices

## Blacklisting
The inherent problem with blacklisting is the approach we’re taking. It allows
us to specify which elements we think are unsafe, making the assumption that we
know everything that could hurt us.

_It’s hard to know everything that’s going to hurt us well in advance, so
whitelisting is generally a more cautious approach, allowing us to specify what
input we trust._

A more practical example would be logging. You will want to whitelist what can
be logged rather than the opposite. Take an example object such as:
```json
{
    email: "rava@gmail.com",
    password: "iloveyou",
    credit_card: "1111 2222 3333 4444",
    birthday: "1999-12-01",
}
```

You could possibly create a blacklist that includes password and credit\_card,
but what would happen when another engineer in the team changes fields from
snake\_case to camelCase?

```json
{
  email: "rava@gmail.com",
  password: "iloveyou",
  creditCard: "1111 2222 3333 4444",
  birthday: "1999-12-01",
}
```
You might end up forgetting to update your blacklist, leading to the credit card
number of your customers being leaked all over your logs.

From a security perspective, whitelisting is a better approach but is often
impractical. Choose your strategy carefully after reviewing both options, none
of the above is suitable without prior knowledge of your system, constraints and
requirements.

## Logging sensitive data
f you develop systems that have to deal with secrets such as passwords, credit 
card numbers, security tokens or personally identifiable information (PII), you 
need to be very careful about how you deal with this data within your 
application, as a simple mistake can lead to a data leak in your 
infrastructure.

You might think that since you have tight restrictions on who has access to 
your logs, you’ll be safe. Chances are that your logs are ingested into a cloud 
service such as **GCP’s StackDriver** or **AWS’ CloudWatch**, meaning that 
there are more attack vectors, such as the cloud provider’s infrastructure 
itself, the communication between your systems, the provider to transmit logs, 
and so on.

### Whitelisting
The solution is to simply avoid logging sensitive information. Whitelist what 
you log and be wary of logging nested entities as there might be sensitive 
information hiding somewhere inside them, such as **req.headers.token**.

Masking

Another solution would be to mask fields, for example, turning a credit card 
number such as _1111 2222 3333 4444_ into _**** **** **** 4444_ before logging 
it.

That can be a dangerous approach. An erroneous deployment or a bug in your 
software might prevent your code from masking the correct fields, leading to 
leaking the sensitive information. As I like to say, use it with caution.

### Inputting sensitive data into the wrong field and logging it 
one particular scenario in which any effort we make not to log sensitive 
information is in vain, when users input sensitive information in the wrong 
place.

You might have a login form with username and password, and users might 
actually input their password in the username field (this can generally happen 
when you auto remember their username so that the input field is not available 
the next time they log in).

## Never Trust The Client
even if your cookies are HttpOnly, storing plaintext data in them is not 
secure, as any client (even curl), could get a hold of those cookies, modify 
them and re-issue a request with a modified version of the original cookie.

Suppose your session cookie contains this information:
```
profile=dXNlcm5hbWU9TGVCcm9uLHJvbGU9dXNlcg==;
```
The string is **base64-encoded**, and anyone could reverse it to get to its 
actual value, **username=LeBron,role=user**. Anyone could, at that point, 
replace user with admin and re-encode the string, altering the value of the 
cookie.

If your system trusts this cookie without any additional check, you’re in 
trouble. You should never trust the client and prevent them from being able to 
easily tamper with the data you’ve handed off. A popular workaround to this 
issue is to encrypt or sign this data, like **JSON Web Tokens** do.

### JWT
A JWT is made of three parts: _headers_, _claims_, and _signatures_, separated 
by a dot.
```
JWT = "$HEADER.$CLAIMS.$SIGNATURE"
```
Each value is base64-encoded, with headers and claims being nothing but an encoded JSON object.
```
$HEADER = BASE64({
  "alg": "HS256",  # HMAC SHA 256
  "typ": "JWT"     # type of the token
})

$CLAIMS = BASE64({
  "sub": "1234567890", # ID of the user
  "name": "John Doe",  # Other attributes...
  "iat": 1516239022    # issued at
})

JWT = "$HEADER.$CLAIMS.$SIGNATURE"
```
The last part, the signature, is the Message Authentication Code (abbr. MAC) of
the combined **$HEADER.$CLAIM**, calculated through the algorithm specified in 
the header itself (_HMAC SHA-256_ in our case). Once the MAC is calculated, it 
is **base64-encoded** as well:
```
$HEADER = BASE64({
  "alg": "HS256",
  "typ": "JWT"
})

$CLAIMS = BASE64({
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
})

$SIGNATURE = BASE64(HS256("$HEADER.$CLAIMS", $PRIVATE_KEY))

JWT = "$HEADER.$CLAIMS.$SIGNATURE"
```
JWT is simply composed of three parts: two insecure sets of strings and a 
signed one, which is what we use to verify the authenticity of the token. 
Without the signature, JWTs would be insecure and (arguably) useless, as the 
information they contain is simply _base64-encoded_

**Note:**

> **If you’re planning to hand over critical information to the client, signing 
> or encrypting it is the only way forward.**

It depends on how you use them. Google, for example, allows authentication to 
their APIs through JWTs. The trick is to use safe, long secrets or a 
cryptographically secure signing algorithm, and understand the use-case you’re presented with. JWTs also don’t make any effort to encrypt the data they hold, and they’re only concerned with validating its authenticity. Understand these trade-offs and make your own educated choice.

In addition, you might want to consider **PASETO**, “Platform Agnostic SEcurity 
TOkens.” They were designed with the explicit goal to provide the flexibility 
and feature-set of JWTs without some of the design flaws that have been 
highlighted earlier on.

## Generating Session IDs
Session IDs (often stored in cookies) should not resemble a known pattern or be
generally guessable. Using an auto-incrementing sequence of integers as IDs 
would be a terrible choice, as an attacker could just log in, receive the 
session ID **X** and then replace it with **X ± N**, where N is a small number 
to increase chances of that being an identifier of a recent, valid session.

### Generating secure IDs

The simplest choice would be to use a cryptographically secure function that 
generates a random string. This is usually not a hard task to accomplish. 
Let’s take the Beego framework, very popular among Golang developers, as an 
example; the function that generates session IDs is:
```go
package session

import (
	"crypto/rand"
)

func (manager *Manager) sessionID() (string, error) {
	b := make([]byte, manager.config.SessionIDLength)
	n, err := rand.Read(b)
	if n != len(b) || err != nil {
		return "", fmt.Errorf("Could not successfully read from the system CSPRNG")
	}
	return manager.config.SessionIDPrefix + hex.EncodeToString(b), nil
}
```
Six lines of code and secure session IDs. As we mentioned earlier, nothing else 
needs to be involved. In this example, a random session ID is generated using 
Go’s native rand.Read(...) method. This method works by generating random bytes 
of a given length (in our case, the length of a session ID). Once the ID is 
generated, it is combined with a session ID prefix.

In general, you won’t need to write this code yourself, as frameworks provide 
the basic building blocks to secure your application out of the box.

## Querying Your Database While Avoiding SQL Injections
The only thing you need to remember when fighting an injection attack is to 
never trust the client. If you receive data from a client, make sure it’s 
**validated**, **filtered** and **innocuous**, then pass it to your database.

Most frameworks and libraries provide you with the tools needed to _sanitize_ 
data before feeding it to a database. The simplest solution is to use 
**prepared statements**, a mechanism offered by most databases that prevents 
SQL injections altogether.

### Prepared statements: Behind the scenes
They’re very straightforward, but often misunderstood. The typical API of a 
prepared statement looks like this:
```
query = `SELECT * FROM users WHERE id = ?`
db.execute(query, id)
```

As you can see, the base query is separated from the external variables that 
need to be embedded in the query. What most database drivers will eventually do
is send the query to the database so that it can prepare an execution plan for 
the query itself. That execution plan can also be reused for the same query 
using different parameters, _so prepared statements have performance benefits 
as well_. Separately, the driver will also send the parameters to be used in 
the query.

At that point the database will sanitize them, and execute the query with the 
sanitized parameters.

There are two key takeaways in this process:

- The query and parameters are never joined before being sent to the database, 
as it’s the database itself that performs this operation
- You delegate sanitization to a built-in database mechanism, and that is 
likely to be more effective than any sanitization mechanism we could have come 
up with by ourselves

## Dependencies With Known Vulnerabilities
Chances are that the application you’re working on right now depends on a 
plethora of open-source libraries.

It isn’t so bad to use open-source libraries, after all, they’re probably safer
than most of the code we write ourselves. But forgetting to update them, 
especially when a security fix is released, is a genuine problem we face every 
day.

Luckily, programs like npm provide tools to identify outdated packages with 
known vulnerabilities. We can simply try to install a dependency with a known 
vulnerability and run **npm audit fix**, and npm will do the rest for us.

You can always rely on external services to scan your software and point out 
any library with known vulnerabilities. GitHub offers this service for all 
their repositories, and you might find it convenient if your codebase is 
already hosted there.
If you prefer using a different platform, you could try _gitlab.com_. In 2018 
it acquired _Gemnasium_, a product that offered vulnerability scanning, in 
order to compete with GitHub’s offering. If you prefer to use a tool that does 
not require code hosting, snyk.io would probably be your best bet. It’s 
trusted by massive companies like Google, Microsoft and SalesForce, and offers 
different tools for your applications, not just dependency scanning.

## Session Invalidation in a Stateless Architecture
If you’ve ever built a web architecture, chances are that you’ve heard how 
stateless architectures scale better due to the fact that they do not have to 
keep track of state. This is true and represents a security risk, especially in
the context of authentication state.

In a typical **stateful architecture**, a client is issued a _session ID_ which 
is stored on the server and linked to the user ID. When the client requests 
information from the server, it includes the session ID, so that the server 
knows a particular request was made on behalf of a user with a particular ID. 
This requires the server to store a list of all the session IDs it generated 
with a link to the user ID, and it can be a costly operation.

JWTs rose to prominence due to the fact that they easily allow stateless 
authentication between the client and the server so that the server doesn’t 
have to store additional information about the session. A JWT can include a 
user ID, and the server can simply verify its signature on-the-fly, without 
having to store a mapping between a session ID and a user ID.

### True stateless architectures are difficult to secure
The issue with **stateless authentication tokens** (and not just JWTs) lies in 
a simple security aspect, it is hard to invalidate tokens, as the server has no
knowledge of each one generated since they’re not stored anywhere. If I logged 
in on a service yesterday and my laptop gets stolen today, an attacker could 
simply use my browser and would still be logged in on the stateless service, as
there is no way for me to invalidate the previously-issued token.

### Solution: take the middle ground

This can be easily circumvented, but it requires us to drop the notion of 
running a completely stateless architecture, as there will be some 
state-tracking required if we want to be able to invalidate JWTs. The key here 
is to find a sweet spot between stateful and stateless, taking advantage of 
both the pros of _statelessness (performance)_ and _statefulness (more 
control)_.

Let’s suppose we want to use JWTs for authentication, we could issue a token 
containing a few pieces of information for the user
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkxlYnJvbiBKYW1lcyIsImlhdCI6MTUxNjIzOTAyMn0
.UJNHBHIBipS_agfTfTpqBmyOFaAR4mNz7eOwLOKUdLk

```
```json
{
  "sub":"1234567890",
  "name":"Lebron James",
  "iat":1516239022
}
```
As you can see, we included an **issued at (iat)** field in the token, which 
can help us invalidate expired tokens. You could then implement a mechanism 
whereby the user can revoke all previously issued tokens by simply clicking a 
button that saves a timestamp in a **last_valid_token_date** field in the 
database.

The authentication logic you would then need to implement for verifying the 
validity of the token would look like this
```javascript
function authenticate(token):
  if !validate(token):
    return false
  
  payload = get_payload(token)
  user_data = get_user_from_db(payload.name)

  if payload.iat < user_data.last_valid_token_date:
    return false

  return true
```

### Minimizing database hits

Unfortunately, this requires you to hit the database every time the user logs 
in, which might go against your goal of scaling more easily through being 
stateless. An ideal solution to this problem would be to use two tokens, a 
**long-lived** one and a **short-lived** one (e.g., one to five minutes).

When your servers receive a request:

- If it has the **long-lived** one only, validate it and do a database check as 
well. If the process is successful, issue a new short-lived one to go with the 
**long-lived** one
- If it carries both tokens, simply validate the **short-lived** one. If it’s 
expired, repeat the process on the previous point. If it’s valid instead, 
there’s no need to check the **long-lived** one as well.

This allows you to keep a session active for a very long time (the validity of 
the long-lived token) but only check for its validity on the database every 
_**N**_ minutes depending on the validity of the _short-lived_ token. Every 
time the short-lived token expires, you can go ahead and re-validate the 
_long-lived_ one, hitting the database.

Other major companies, such as Facebook, keep track of all of your sessions in 
order to offer an increased level of security. This approach definitely costs 
more, but I’d argue it’s essential for such a service where the safety of its 
users’ information is extremely important. As we stated multiple times before, 
choose your approach after carefully reviewing your priorities and goals.

