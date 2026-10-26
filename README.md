# Proseth AIOps collector

The agent for the **Proseth AIOps** platform. It runs on a small Ubuntu/Debian
machine at your site and connects **outbound** to the platform. Your
monitoring tells it when something is wrong; the platform's engineers (and its
AI investigator) use it to look at the affected machine from inside your
network.

This repository holds only the agent and its installer. It is public so you can
read exactly what you are about to install.

## What it does — and does not

* **It connects out. Nothing connects in** — except, if you turn it on, your own
  monitoring server posting alerts to it on port **9917** on your LAN.
* It runs **one command at a time** that the platform asks for, against machines
  you registered with the platform, and streams the output back. Read-only
  diagnostics run directly; anything that **changes** a machine is approved by a
  named engineer first (or by a fix you pre-approved as a runbook).
* Credentials for your machines arrive with each job and live in memory for its
  duration. They are not stored here.
* No telemetry, no phone-home, no address baked in. Updates happen when the
  platform asks, by fetching this repository's `main`.

## Requirements

Ubuntu 22.04+ or Debian 12+, 1 vCPU / 1 GB RAM is plenty, outbound TCP to the
platform on 9443, and outbound HTTPS to GitHub/PyPI/Ubuntu archives during install.

## Install

Create the collector in the platform first (Collectors → Add collector). It
gives you a ready-to-paste command with the token filled in, like:

```bash
curl -fsSLO https://raw.githubusercontent.com/prosethsolutionsAI/proseth-aiops-agent/main/install.sh && \
sudo AIOPS_NONINTERACTIVE=1 AIOPS_PLATFORM_HOST=203.0.113.10 AIOPS_PLATFORM_PORT=9443 \
  AIOPS_COLLECTOR_NAME='acme-dc-01' AIOPS_TOKEN=pax_xxxxxxxx_yyyyyyyy AIOPS_ALERTS=1 bash install.sh
```

Or run `sudo bash install.sh` and answer the questions. Re-running is safe.

The installer checks it can reach the platform **before** changing anything,
pins the platform's certificate (prints its fingerprint — compare it if the path
is not trusted), installs the agent under `/opt/proseth-aiops-agent` as the
unprivileged `proseth-aiops` user, and starts `proseth-aiops-agent.service`.

## Sending it alerts

`POST http://<collector>:9917/alert/<source>` with header
`Authorization: Bearer <token>` (`sudo proseth-aiops-agent --alert-secret`).
`<source>` is `zabbix`, `alertmanager`, `wazuh` or `generic`.

**Prometheus Alertmanager**
```yaml
receivers:
  - name: proseth
    webhook_configs:
      - url: http://203.0.113.20:9917/alert/alertmanager
        send_resolved: true
        http_config: { authorization: { type: Bearer, credentials: TOKEN } }
```

**Zabbix** — Media type *Webhook*, parameters `url`, `token`, `event_value={EVENT.VALUE}`,
`host={HOST.HOST}`, `host_ip={HOST.IP}`, `trigger_name={EVENT.NAME}`,
`severity={EVENT.SEVERITY}`, `message={ALERT.MESSAGE}`, script:

```javascript
var p = JSON.parse(value), r = new HttpRequest();
r.addHeader('Content-Type: application/json');
r.addHeader('Authorization: Bearer ' + p.token);
r.post(p.url, JSON.stringify({event_value: p.event_value, host: p.host, host_ip: p.host_ip,
  trigger_name: p.trigger_name, severity: p.severity, message: p.message}));
if (r.getStatus() != 202) { throw 'collector answered ' + r.getStatus(); }
return 'OK';
```
Enable recovery operations so resolved problems are reported.

**Anything else**
```bash
curl -X POST http://203.0.113.20:9917/alert/generic -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"web-01","title":"Disk / 95% full","severity":"high","alertname":"HostDiskFull"}'
```

Alerts are written to disk before the `202`, and deleted only when the platform
confirms it stored them — a link outage loses nothing.

## Operating it

```bash
systemctl status proseth-aiops-agent
journalctl -u proseth-aiops-agent -f
proseth-aiops-agent --check            # version, platform, alerts on/off
sudo proseth-aiops-setup               # change address / token / alerts
```

| Path | Contents |
|---|---|
| `/opt/proseth-aiops-agent` | agent code + venv (root-owned; the agent cannot rewrite itself) |
| `/etc/proseth-aiops-agent/config.json` | platform address, token, alert secret (mode 640) |
| `/etc/proseth-aiops-agent/platform-ca.crt` | the pinned platform certificate authority |
| `/var/lib/proseth-aiops-agent/alerts` | alerts waiting for the platform's confirmation |

The service account may run exactly one command as root,
`/usr/local/sbin/proseth-aiops-selfupdate` (no arguments), used by **Upgrade** in
the platform. Remove `/etc/sudoers.d/proseth-aiops-agent` to upgrade only by hand.

## Removing it

```bash
sudo systemctl disable --now proseth-aiops-agent
sudo rm -rf /opt/proseth-aiops-agent /etc/proseth-aiops-agent /var/lib/proseth-aiops-agent \
  /etc/systemd/system/proseth-aiops-agent.service /etc/sudoers.d/proseth-aiops-agent \
  /usr/local/bin/proseth-aiops-agent /usr/local/bin/proseth-aiops-setup /usr/local/sbin/proseth-aiops-selfupdate
sudo userdel proseth-aiops
```

## Licence

MIT.
