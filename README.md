# Pre Update Password Action Service (WSO2 IS 7.3.0)

A Spring Boot service that implements a WSO2 Identity Server **Pre Update Password**
action: IS calls this service before a password is hashed and stored, and the service
can veto the change. The sample policy rejects any password containing the corporate
token `wso2` or the user's own username.

- **Product:** WSO2 Identity Server 7.3.0 (on-premises)
- **Service stack:** Java 21 + Spring Boot 4.1.1
- **Exposure:** direct `localhost` — no tunnel required when IS and the service share a host

---

## Table of contents

1. [What this service does](#1-what-this-service-does)
2. [Prerequisites](#2-prerequisites)
3. [The contract](#3-the-contract)
4. [Project layout](#4-project-layout)
5. [Run and test locally](#5-run-and-test-locally)
6. [Make the service reachable from IS](#6-make-the-service-reachable-from-is)
7. [Register the action in the Console](#7-register-the-action-in-the-console)
8. [Test the flow end to end](#8-test-the-flow-end-to-end)
9. [Troubleshooting](#9-troubleshooting)
10. [Design notes](#10-design-notes)
11. [Appendix — server-side tuning](#11-appendix--server-side-tuning)

---

## 1. What this service does

WSO2 IS normally validates a password itself, hashes it and stores it. The Actions
framework lets you insert your own code into that pause: IS stops, POSTs the new
password to an endpoint you own, and waits for your verdict.

```
  My Account  ┐
  Console     ├─ (1) new password submitted
  SCIM API    ┘          │
                         ▼
              WSO2 Identity Server ──(2) HTTP POST, flow BLOCKED──► This service
                         │                                            POST /actions/validate-password
                         │                                                      │
                         │◄──────(3) SUCCESS / FAILED / ERROR ─────────────────┘
                         ▼
              (4) hash + persist, or reject the request
```

Three answers are possible, and nothing else:

| `actionStatus` | HTTP status returned | What IS does |
|---|---|---|
| `SUCCESS` | 200 | hashes and stores the password |
| `FAILED` | 200 | blocks it; the caller gets **400** carrying `failureDescription` |
| `ERROR` | 500 | blocks it; the caller gets a generic **500** |

`FAILED` means "I checked, the policy says no." `ERROR` means "I could not decide."
Business rules always use `FAILED`, so the end user sees a usable message.

> **The flow is fail-closed.** A timeout, a refused connection, or an unparsable
> response all abort the password change. There is no "skip the extension and
> continue" mode. This service is on the critical path for every password change
> in the deployment.

---

## 2. Prerequisites

| Requirement | Notes |
|---|---|
| WSO2 IS 7.3.0 | started and reachable at `https://localhost:9443` |
| JDK 21 | `java -version` |
| Maven 3.9+ (or the bundled `./mvnw`) | |
| `curl` and `jq` | for the test steps |
| A test user | e.g. `alexsmith` in the `PRIMARY` user store, with a known password |

No ngrok, no public DNS, no TLS certificate needed for an all-local lab setup — see
[section 6](#6-make-the-service-reachable-from-is) for why, and for the Docker/LAN
variants.

---

## 3. The contract

### 3.1 Request payload

This is what IS 7.3.0 actually POSTs to `/actions/validate-password`:

```json
{
  "actionType": "PRE_UPDATE_PASSWORD",
  "requestId": "b69404cc-3f64-458d-a5b5-7df820a86279",
  "flowId": "f7893510-2134-4bc5-a5b5-7df820a86279",
  "event": {
    "tenant":    { "id": "-1234", "name": "carbon.super" },
    "userStore": { "id": "UFJJTUFSWQ==", "name": "PRIMARY" },
    "user": {
      "id": "8eebb941-51e1-4d13-9d5a-81da190383ae",
      "claims": [
        { "uri": "http://wso2.org/claims/username", "value": "alexsmith" }
      ],
      "updatingCredential": {
        "type":   "PASSWORD",
        "format": "PLAIN_TEXT",
        "value":  "PasswordToValidate123!"
      }
    },
    "initiatorType": "USER",
    "action": "UPDATE"
  }
}
```

When the action is configured to share the password hashed instead:

```json
"updatingCredential": {
  "type": "PASSWORD",
  "format": "HASH",
  "value": "h3bxCOJHqx4rMjBCwEnCZkB8gfutQb3h6N/Bu2b9Jn4=",
  "additionalData": { "algorithm": "SHA256" }
}
```

Two things worth calling out:

- The password lives at `event.user.updatingCredential.value`, not at the top level of
  the payload.
- `event.user.claims` contains **only** the attributes the action is configured to
  share. Without sharing the username claim, the username rule in
  [`PasswordPolicyValidator`](src/main/java/com/example/iam/pre_update_password_action_service/service/PasswordPolicyValidator.java)
  never fires.

These are modeled as Java records in
[`ActionRequest`](src/main/java/com/example/iam/pre_update_password_action_service/dto/ActionRequest.java) —
only the fields this service uses are declared, and Spring's default Jackson config
ignores unknown fields rather than failing on them.

### 3.2 Response payloads

```json
{ "actionStatus": "SUCCESS" }
```

```json
{
  "actionStatus": "FAILED",
  "failureReason": "forbidden_token_in_password",
  "failureDescription": "The password must not contain the company term 'wso2'."
}
```

```json
{
  "actionStatus": "ERROR",
  "errorMessage": "server_error",
  "errorDescription": "Error while evaluating the password policy."
}
```

See [`ActionResponse`](src/main/java/com/example/iam/pre_update_password_action_service/dto/ActionResponse.java).

### 3.3 Identifying the flow

`initiatorType` and `action` together identify the entry point that triggered the
password change:

| `initiatorType` | `action` | Flow | Needs contract |
|---|---|---|---|
| USER | UPDATE | user changes password in My Account / SCIM `Me` | v1.0 |
| USER | RESET | forgot-password recovery | v1.0 |
| USER | REGISTER | self-registration | **v2.0** |
| ADMIN | UPDATE | admin resets a password in Console / SCIM Users | v1.0 |
| ADMIN | RESET | admin-forced reset, completed by the user | v1.0 |
| ADMIN | INVITE | invited user sets their first password | v1.0 |
| ADMIN | REGISTER | admin creates a user **with** a password | **v2.0** |
| APPLICATION | UPDATE / REGISTER | provisioning integration via SCIM | v1.0 / v2.0 |

If the action is on the v1.x contract, creating a user with a password and
self-registration will **not** trigger it — the password saves normally and the service
logs nothing. This is the most common "it isn't working" symptom; see
[section 9.1](#91-password-updates-succeed-and-the-service-logs-nothing).

---

## 4. Project layout

```
pre-update-password-action-service/
├── pom.xml
└── src/
    ├── main/
    │   ├── java/com/example/iam/pre_update_password_action_service/
    │   │   ├── PreUpdatePasswordActionServiceApplication.java
    │   │   ├── dto/ActionRequest.java
    │   │   ├── dto/ActionResponse.java
    │   │   ├── service/PasswordPolicyValidator.java   ← the policy rules
    │   │   ├── web/PasswordActionController.java      ← the HTTP endpoint
    │   │   └── security/BasicAuthFilter.java           ← constant-time Basic Auth check
    │   └── resources/application.yml
    └── test/java/com/example/iam/pre_update_password_action_service/
        └── PreUpdatePasswordActionServiceApplicationTests.java
```

Design choices worth knowing before reading the code:

- **Typed records instead of `Map<String, Object>`.** With maps, a mistake surfaces at
  runtime as a `ClassCastException` or a silent `null`; with records the compiler
  catches it.
- **Rules are isolated in `PasswordPolicyValidator`**, with no HTTP in sight, so they
  can be unit-tested without starting a server.
- **Forbidden tokens and thresholds are configuration, not code** (`application.yml`),
  so changing the policy doesn't require a rebuild.
- **Authentication is a single `OncePerRequestFilter`**, not
  `spring-boot-starter-security`. IS sends whatever is configured under the action's
  Authentication section as a plain `Authorization` header, so one constant-time header
  comparison is all that's needed.

---

## 5. Run and test locally

Do this **before** touching the Console. Fixing a rule here is a five-second loop;
fixing it through a full IS password flow is not.

```bash
./mvnw clean package
java -jar target/pre-update-password-action-service-0.0.1-SNAPSHOT.jar

curl http://localhost:8080/actions/health      # → UP
```

### 5.1 Exercise the rules

The default credentials in `application.yml` are `admin` / `admin` (override via the
`ACTION_AUTH_USERNAME` / `ACTION_AUTH_PASSWORD` environment variables before exposing
this anywhere beyond a local lab).

```bash
#!/usr/bin/env bash
BASE="${1:-http://localhost:8080}"
AUTH="admin:admin"

call() {
  echo "--- $1 (password: $2)"
  curl -s -u "$AUTH" -H 'Content-Type: application/json' \
    -X POST "$BASE/actions/validate-password" -d "{
      \"actionType\": \"PRE_UPDATE_PASSWORD\",
      \"requestId\": \"test-$RANDOM\",
      \"event\": {
        \"tenant\": { \"name\": \"carbon.super\" },
        \"userStore\": { \"name\": \"PRIMARY\" },
        \"user\": {
          \"id\": \"8eebb941-51e1-4d13-9d5a-81da190383ae\",
          \"claims\": [ { \"uri\": \"http://wso2.org/claims/username\", \"value\": \"alexsmith\" } ],
          \"updatingCredential\": {
            \"type\": \"PASSWORD\", \"format\": \"PLAIN_TEXT\", \"value\": \"$2\"
          }
        },
        \"initiatorType\": \"USER\", \"action\": \"UPDATE\"
      }
    }"
  echo -e "\n"
}

call "expect SUCCESS"                'GoodPassphrase!42'
call "expect FAILED forbidden token" 'MyWso2Password1!'
call "expect FAILED username inside" 'alexsmith2026!'
call "expect FAILED too short"       'Ab!3x'
```

Expected output:

```json
{"actionStatus":"SUCCESS"}
{"actionStatus":"FAILED","failureReason":"forbidden_token_in_password","failureDescription":"The password must not contain the company term 'wso2'."}
{"actionStatus":"FAILED","failureReason":"username_in_password","failureDescription":"The password must not contain your username."}
{"actionStatus":"FAILED","failureReason":"password_too_short","failureDescription":"The password must be at least 8 characters long."}
```

Two more worth running:

```bash
# No credentials -> 401
curl -i -X POST http://localhost:8080/actions/validate-password \
  -H 'Content-Type: application/json' -d '{}'

# Malformed payload -> structured ERROR, not a stack trace
curl -s -u admin:admin -X POST \
  http://localhost:8080/actions/validate-password \
  -H 'Content-Type: application/json' -d '{}'
```

---

## 6. Make the service reachable from IS

WSO2's documentation requires the endpoint to be **accessible to WSO2 Identity
Server** — not accessible from the internet. IS is the HTTP *client* here. Guides that
mandate ngrok are written for Asgardeo, where IS runs in WSO2's cloud and genuinely
cannot see your workstation.

On an on-premises lab, IS and this service are usually on the same host, so no tunnel
is needed.

| Topology | Endpoint URL to configure |
|---|---|
| IS and service on the same host | `http://localhost:8080/actions/validate-password` |
| IS in Docker, service on the host | `http://host.docker.internal:8080/actions/validate-password` |
| Both in Docker Compose | `http://password-action:8080/actions/validate-password` |
| IS on another machine on the LAN | `http://192.168.x.x:8080/actions/validate-password` |

On Linux, `host.docker.internal` needs `--add-host=host.docker.internal:host-gateway`
on the IS container.

### 6.1 If the Console rejects an `http://` URL

Serve over TLS locally and trust the certificate on the IS side:

```bash
keytool -genkeypair -alias action -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore action.p12 -storepass changeit \
  -validity 365 -dname "CN=localhost" -ext "SAN=dns:localhost"

keytool -exportcert -alias action -keystore action.p12 \
  -storepass changeit -storetype PKCS12 -rfc -file action.pem

keytool -importcert -alias password-action -file action.pem \
  -keystore $IS_HOME/repository/resources/security/client-truststore.jks \
  -storepass wso2carbon -noprompt
```

Copy `action.p12` into `src/main/resources/`, add to `application.yml`:

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:action.p12
    key-store-password: changeit
    key-store-type: PKCS12
    key-alias: action
```

Restart IS, and use `https://localhost:8443/actions/validate-password`. Skipping the
truststore import produces `PKIX path building failed` in `wso2carbon.log`.

---

## 7. Register the action in the Console

**Console → Actions → Pre Update Password → Add.**

| Field | Value for this lab |
|---|---|
| Action Name | `CorporatePasswordValidator` |
| Endpoint URL | `http://localhost:8080/actions/validate-password` |
| Authentication Type | Basic |
| Username | `admin` (or your overridden `ACTION_AUTH_USERNAME`) |
| Password | `admin` (or your overridden `ACTION_AUTH_PASSWORD`) |
| Password Sharing Format | **Plain text** |
| Shared user attributes | `http://wso2.org/claims/username` |
| Certificate | *(leave empty)* |
| Rules | *(leave empty — fires for every flow)* |
| Status | **Active** |

Save, then confirm the action shows as Active.

### 7.1 The two settings people miss

**Plain text sharing.** The rules are substring searches. You cannot look for the
letters `wso2` inside a SHA-256 digest. The validator deliberately returns `ERROR` when
it receives a hash, so a misconfiguration is loud instead of invisible. Set
`password-policy.fail-closed-on-hash: false` in `application.yml` to approve-and-warn
instead.

**Sharing the username claim.** This is what puts `http://wso2.org/claims/username`
into `event.user.claims`. Without it, the username rule never fires.

### 7.2 Authentication options

| Type | Console fields | Header IS sends |
|---|---|---|
| None | — | *(none)* — development only |
| Basic | Username, Password | `Authorization: Basic base64(u:p)` |
| Bearer | Access Token | `Authorization: Bearer <token>` |
| API Key | Header name, Value | `<HeaderName>: <value>` |

IS sends a **static** configured token for Bearer; it does not run a `client_credentials`
grant on the service's behalf, so an expiring token means an expiring action.

### 7.3 Verify the stored configuration

The Console can look configured while the record is inactive. Ask the API directly:

```bash
curl -k -u admin:admin \
  https://localhost:9443/api/server/v1/actions/preUpdatePassword | jq
```

Confirm `"status": "ACTIVE"` and the correct `endpoint.uri`.

---

## 8. Test the flow end to end

### 8.1 Deterministic test — SCIM

This is `ADMIN/UPDATE`, supported on every contract version, and the HTTP response
shows the verdict directly:

```bash
# Get the user id
curl -k -u admin:admin \
  "https://localhost:9443/scim2/Users?filter=userName+eq+alexsmith" | jq -r '.Resources[0].id'

# Attempt a non-compliant password
curl -k -u admin:admin -X PATCH \
  https://localhost:9443/scim2/Users/<user-id> \
  -H 'Content-Type: application/scim+json' \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      { "op": "replace", "value": { "password": "MyWso2Password1!" } }
    ]
  }'
```

Expected — HTTP 400, the description carried through in `detail`:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "scimType": "invalidValue",
  "detail": "The password must not contain the company term 'wso2'.",
  "status": "400"
}
```

Repeat with `GoodPassphrase!42` → HTTP 200 and the password changes.

### 8.2 Flow matrix

| Case | How to trigger | Expected |
|---|---|---|
| Clean password | My Account → Security → Change password → `GoodPassphrase!42` | saved; service logs `Password accepted` |
| Forbidden token | same, `MyWso2Password1!` | blocked; message shown in the UI |
| Username inside | same, `alexsmith2026!` | blocked |
| Admin update | Console → Users → user → Reset password | fires as `ADMIN/UPDATE` |
| Invite | Console → Users → Add user → invite to set password | fires as `ADMIN/INVITE` |
| Recovery | Login page → Forgot password | fires as `USER/RESET` |
| Self-registration | self-registration portal | fires as `USER/REGISTER` — **v2.0 contract only** |
| Service down | stop the JAR, retry a password change | caller gets 500, password unchanged |

Each call writes one `Action invoked` line plus one decision line to the service
console.

> Through the recovery and invite flows, the message surfaces in the recovery API's own
> shape (`code: 20067`, `message: invalid_format`) rather than carrying
> `failureDescription` verbatim. The block itself still works.

---

## 9. Troubleshooting

### 9.1 Password updates succeed and the service logs nothing

**IS never called the endpoint.** The action is fail-closed, so a refused connection,
timeout, or bad response would have *blocked* the update with a 500. A successful
update with no logs means IS did not attempt the call at all. Check these three things,
in order:

1. **Is the action ACTIVE?** Run the API check in [7.3](#73-verify-the-stored-configuration).
   An empty array means the save never completed; `INACTIVE` means the toggle is off.
2. **Which flow did you test?** Creating a user with a password (`ADMIN/REGISTER`) and
   self-registration (`USER/REGISTER`) need the **v2.0** contract. On v1.x they save
   normally and never call the service. Retest with the SCIM PATCH in
   [8.1](#81-deterministic-test--scim).
3. **Which organization are you in?** Only the root organization applies this action.
   `/console` is root, `/o/<uuid>/console` is a sub-organization, `/t/<tenant>/console`
   is a different tenant — the test user must be in the same one.

Also confirm no **Rules** are configured that exclude the flow under test.

### 9.2 Make IS tell you what it is doing

In `<IS_HOME>/repository/conf/log4j2.properties`:

```properties
logger.actionMgt.name = org.wso2.carbon.identity.action
logger.actionMgt.level = DEBUG

logger.preUpdatePwd.name = org.wso2.carbon.identity.user.pre.update.password.action
logger.preUpdatePwd.level = DEBUG
```

**Then append both logger keys to the comma-separated `loggers` list at the top of the
file** — this is the most common reason "I enabled DEBUG and saw nothing":

```properties
loggers = AUDIT_LOG, ..., actionMgt, preUpdatePwd
```

The file has a monitor interval and usually takes effect within a minute; restart IS if
it doesn't. Repeat the test and watch `repository/logs/wso2carbon.log`.

- Lines about resolving or executing the action → IS is trying; the errors there name
  the problem.
- Complete silence → IS is not looking up an action for this flow; go back to 9.1.

### 9.3 Wire-level check

```bash
sudo tcpdump -i lo -n port 8080
```

Run a password update. Packets mean IS is calling the service and the fault is local;
no packets confirms IS never dialled.

```bash
curl -v http://localhost:8080/actions/health   # service is up
ss -ltnp | grep 8080                           # and it's the java process on that port
```

### 9.4 Symptom table

| Symptom | Cause |
|---|---|
| Password saves, no logs | see 9.1 — IS never called |
| All password updates fail with 500 | the service is down, slow, or returning a body IS can't parse |
| 401 in the service log | Console credentials differ from `action.auth.*` |
| `PKIX path building failed` in `wso2carbon.log` | endpoint certificate not in `client-truststore.jks` (see 6.1) |
| Always `unsupported_password_format` | Password Sharing Format is hashed; switch to plain text |
| Username rule never triggers | `http://wso2.org/claims/username` is not in the shared attributes |
| Read timeout on the IS side | service too slow; tune the client (see 11.1) |
| Connection refused with IS in Docker | `localhost` inside a container is the container; use `host.docker.internal` |

---

## 10. Design notes

**In-flight failures and availability.** The action is fail-closed, with no switch to
change it. If the service times out, refuses the connection, or returns anything
unparsable, the update counts as an execution error: it's abandoned and the caller gets
HTTP 500. That's the correct default for a security control, but it makes this service
part of the critical path for every password change in the deployment — so it needs
comparable availability, plus tuned timeouts and retries (see
[section 11](#11-appendix--server-side-tuning)). Lenient behaviour for a specific
condition is expressed inside the service by returning `SUCCESS` — exactly what
`fail-closed-on-hash: false` does.

**Why plain-text password sharing exists.** A hash is one-way, so a digest only
supports equality checks against pre-computed digests. Anything semantic — does this
contain the company trademark, does it contain the username, is it a keyboard walk —
needs the cleartext. That's a deliberate trade-off, not a default, and it raises the bar
on protections across the trust boundary: TLS on the endpoint, authentication so
nothing else can post to it, and (optionally) JWE encryption of `updatingCredential`
with the service's public certificate so the password survives a TLS-terminating
middlebox. On the service side: never log it, never persist it, hold it in memory only
for the length of the call, and prefer hashed sharing whenever the rules can work with
a digest.

**Flow differentiation.** `event.initiatorType` and `event.action` together identify
the flow (table in [3.3](#33-identifying-the-flow)). `USER/UPDATE` is a self-service
change, `ADMIN/INVITE` is an administrator onboarding someone, `APPLICATION/UPDATE` is
a provisioning integration. A policy can branch on that pair where it should differ —
e.g. skipping history checks during `REGISTER` where there is no history, or applying
stricter rules to admin-set passwords. The action's Rules configuration can also filter
earlier, so IS only invokes the service for the flows it cares about.

---

## 11. Appendix — server-side tuning

### 11.1 Action HTTP client

`<IS_HOME>/repository/conf/deployment.toml`:

```toml
[actions]
http_client.connection_timeout = 2000
http_client.read_timeout = 6000
http_client.connection_request_timeout = 2000
http_client.request_retry_count = 2
```

Confirm the exact key names against the configuration catalog for your build. Raise
`read_timeout` only as far as users should reasonably wait — this delay sits in front
of every password change.

### 11.2 Production hardening checklist

- [ ] Endpoint served over TLS with a certificate the IS truststore accepts
- [ ] Authentication enabled, secrets injected as environment variables, never committed
- [ ] Password never logged, never persisted, never forwarded to a third party unencrypted
- [ ] Service deployed with redundancy — it is on the critical path and fail-closed
- [ ] Timeouts and retries tuned, with alerting on action-execution errors
- [ ] Rules configured so the action only fires for the flows that need it
- [ ] Hashed sharing used wherever the rules can work with a digest
