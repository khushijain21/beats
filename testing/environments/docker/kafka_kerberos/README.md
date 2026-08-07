# Kafka GSSAPI against cloud Active Directory

End-to-end guide: local Kafka broker with **SASL/GSSAPI**, using a GCP
Windows **Active Directory** DC as the KDC (not an in-container MIT `krb5kdc`).

This is what made `TestKafkaPublishKerberosAware` pass.

## Architecture

```
Beats test (Mac)  --GSSAPI-->  Kafka container (:9095)
       |                              |
       |  AS-REQ / TGS-REQ            |  keytab login
       v                              v
         AD DC = KDC (TCP/UDP 88)
         [VM-IP]
         realm INGEST.EXAMPLE.COM
```

| Role | Principal / account | Auth |
|------|---------------------|------|
| KDC | AD DC `khushi-ad-windows-server` | — |
| Kafka broker | `kafka/localhost@INGEST.EXAMPLE.COM` (AD user `kafka_localhost`) | **keytab** |
| Beats / test client | `beats@INGEST.EXAMPLE.COM` | **password** `Testing1!` |

## Defaults

| Setting | Value |
|---------|--------|
| AD VM | `khushi-ad-windows-server` (GCP `elastic-platform-ingest`, `us-central1-a`) |
| AD public IP / KDC | `[VM-IP]` |
| Domain / NetBIOS / realm | `ingest.example.com` / `INGEST` / `INGEST.EXAMPLE.COM` |
| GSSAPI listener | `localhost:9095` |
| PLAINTEXT (healthcheck only) | `localhost:9092` (inside container) |
| Broker keytab path | `testing/environments/docker/kafka_kerberos/secrets/kafka_localhost.keytab` |
| Client `krb5.conf` | `libbeat/outputs/kafka/testdata/krb5.conf` |

---

## 1. GCP firewall

From your laptop (and later CI), open Kerberos to the AD VM.

Create a VPC firewall rule targeting the VM’s **network tags**:

| Field | Value |
|-------|--------|
| Direction | Ingress |
| Targets | Specified target tags (same tags as the VM) |
| Source IPv4 | your public IP `/32` (e.g. `49.x.x.x/32`) |
| Protocols / ports | `tcp:88` and `udp:88` |
| Also keep | `tcp:3389` for RDP (often already open) |

Check from your Mac:

```bash
# TCP 88 should be open (was timeout before the rule)
python3 - <<'PY'
import socket
host = "[VM-IP]"
for port in (88, 3389):
    s = socket.socket(); s.settimeout(5)
    try:
        s.connect((host, port)); print(f"TCP {port}: open")
    except Exception as e:
        print(f"TCP {port}: {e}")
    finally:
        s.close()
PY
```

---

## 2. RDP into the Windows AD VM

GCP Console cannot create AD users / SPNs / keytabs — you need a Windows session.

1. Install **Windows App** (Microsoft Remote Desktop) on Mac.
2. **Add PC** → PC name: `[VM-IP]` (IP goes here, **not** in the username).
3. Credentials: username from GCP **Set Windows password** (e.g. `khushi_jain`), not `user@ip`.
4. If the screen is black: wait, reconnect, or **Reset** the VM in GCP, then retry.

---

## 3. Create AD principals (PowerShell as Admin)

On the Windows VM:

```powershell
Import-Module ActiveDirectory

# --- Client user for Beats / tests ---
# Password must meet AD complexity (plain "testing" is rejected).
New-ADUser -Name "beats" -SamAccountName "beats" `
  -UserPrincipalName "beats@ingest.example.com" `
  -AccountPassword (ConvertTo-SecureString "Testing1!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

Set-ADUser beats -KerberosEncryptionType AES128,AES256 -ChangePasswordAtLogon $false

# If the user already exists but password failed earlier:
# Set-ADAccountPassword -Identity beats -Reset -NewPassword (ConvertTo-SecureString "Testing1!" -AsPlainText -Force)
# Enable-ADAccount -Identity beats
# Set-ADUser beats -PasswordNeverExpires $true -ChangePasswordAtLogon $false

# --- Broker service account ---
New-ADUser -Name "kafka_localhost" -SamAccountName "kafka_localhost" `
  -UserPrincipalName "kafka_localhost@ingest.example.com" `
  -AccountPassword (ConvertTo-SecureString "KafkaBroker1!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

Set-ADUser kafka_localhost -KerberosEncryptionType AES128,AES256 -ChangePasswordAtLogon $false
```

### SPN (host only — do **not** put `@REALM` in setspn)

```powershell
setspn -A kafka/localhost kafka_localhost

# Verify — should list only kafka_localhost
setspn -Q kafka/localhost
setspn -L kafka_localhost
setspn -X   # should report 0 duplicate SPN groups
```

### Export keytab

```powershell
Get-ADUser kafka_localhost   # must succeed

ktpass /princ kafka/localhost@INGEST.EXAMPLE.COM `
  /mapuser kafka_localhost@INGEST.EXAMPLE.COM `
  /pass KafkaBroker1! `
  /out C:\kafka_localhost.keytab `
  /crypto AES256-SHA1 `
  /ptype KRB5_NT_PRINCIPAL
```

Notes from debugging:

- Use `/mapuser kafka_localhost@INGEST.EXAMPLE.COM` (UPN). Short name alone can fail with `DsCrackNames returned 0x2`.
- SPN for `setspn` is `kafka/localhost`, **not** `kafka/localhost@INGEST.EXAMPLE.COM`.
- Run these in **PowerShell**, not `cmd.exe` (`New-ADUser` is a cmdlet).

---

## 4. Copy the keytab to your Mac (binary-safe)

**Do not** open/edit the `.keytab` in a text editor — that produces a file of zeros and Kafka fails with `LoginException` / password prompt.

### Recommended: Base64

On Windows:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\kafka_localhost.keytab"))
```

On Mac:

```bash
mkdir -p /Users/khushijain/Documents/beats/testing/environments/docker/kafka_kerberos/secrets

# paste the Base64 string between the quotes
echo 'PASTE_BASE64_HERE' | base64 -d > \
  /Users/khushijain/Documents/beats/testing/environments/docker/kafka_kerberos/secrets/kafka_localhost.keytab

# Must say "Kerberos Keytab file", not "data" / all zeros
file testing/environments/docker/kafka_kerberos/secrets/kafka_localhost.keytab
```

Example of a valid decode check:

```text
Kerberos Keytab file, realm=INGEST.EXAMPLE.COM, principal=kafka/localhost, ...
```

---

## 5. Start Kafka (points at AD)

```bash
cd /Users/khushijain/Documents/beats/libbeat

ES_BEATS=$(cd .. && pwd) TESTING_ENVIRONMENT=snapshot \
  docker compose up --build -d kafka_kerberos

# After replacing the keytab, force recreate (restart alone can hit Docker mount glitches)
ES_BEATS=$(cd .. && pwd) TESTING_ENVIRONMENT=snapshot \
  docker compose up -d --force-recreate kafka_kerberos

# Expect: Successfully logged in + "Kafka Kerberos broker is ready"
ES_BEATS=$(cd .. && pwd) TESTING_ENVIRONMENT=snapshot \
  docker compose logs --tail=40 kafka_kerberos
```

Compose mounts:

`secrets/kafka_localhost.keytab` → `/etc/kafka_localhost.keytab`

Env defaults (`AD_KDC_HOST=[VM-IP]`, realm, etc.) are in `libbeat/docker-compose.yml`.

---

## 6. Run the integration test

```bash
cd /Users/khushijain/Documents/beats/libbeat

go test -tags integration -v -run TestKafkaPublishKerberosAware ./outputs/kafka/
```

Hardcoded in `kafka_kerberos_integration_test.go`:

- host `localhost:9095`
- realm `INGEST.EXAMPLE.COM`
- user `beats` / password `Testing1!`
- `testdata/krb5.conf` → KDC `[VM-IP]`

Expected: `--- PASS: TestKafkaPublishKerberosAware`

---

## 7. Optional sanity checks

From the Kafka container (against AD):

```bash
# Client password works
docker exec -it libbeat-kafka_kerberos-1 bash -c \
  'printf "%s\n" "Testing1!" | kinit beats@INGEST.EXAMPLE.COM && klist && kdestroy'

# Broker keytab works
docker exec -it libbeat-kafka_kerberos-1 bash -c \
  'kinit -k -t /etc/kafka_localhost.keytab kafka/localhost@INGEST.EXAMPLE.COM && klist && kdestroy'

# Service ticket for kafka/localhost (after client kinit)
docker exec -it libbeat-kafka_kerberos-1 bash -c \
  'printf "%s\n" "Testing1!" | kinit beats@INGEST.EXAMPLE.COM && kvno kafka/localhost@INGEST.EXAMPLE.COM && klist -e'
```

---

## Troubleshooting cheat sheet

| Symptom | Fix |
|---------|-----|
| TCP 88 timeout | GCP firewall: tcp+udp 88 to VM tags from your IP |
| RDP black screen | Reconnect / reset VM / lower display resolution |
| `New-ADUser` not recognized | Use PowerShell, not cmd; `Import-Module ActiveDirectory` |
| Password complexity error | Use e.g. `Testing1!`, not `testing` |
| `DsCrackNames returned 0x2` | `/mapuser kafka_localhost@INGEST.EXAMPLE.COM` |
| Duplicate SPN | `setspn -Q` / `-X`; SPN without `@REALM` |
| Keytab file is all zeros | Re-copy via Base64; never paste binary into a text editor |
| Kafka `LoginException` / asks for password | Bad/missing keytab mount; recreate container |
| GSSAPI auth failed after broker login OK | Encryption mismatch (RC4 ticket vs AES keytab); set AES on accounts, regenerate keytab |
| Test uses wrong password | Password is hardcoded as `Testing1!` in the test |

---

## Repo files involved

| Path | Purpose |
|------|---------|
| `testing/environments/docker/kafka_kerberos/` | Dockerfile, `run.sh`, JAAS/krb5 templates, healthcheck |
| `testing/environments/docker/kafka_kerberos/secrets/kafka_localhost.keytab` | AD-exported broker keytab (local only; do not commit secrets) |
| `libbeat/docker-compose.yml` | `kafka_kerberos` service |
| `libbeat/outputs/kafka/kafka_kerberos_integration_test.go` | GSSAPI publish/consume test |
| `libbeat/outputs/kafka/testdata/krb5.conf` | Client Kerberos config → AD KDC |
