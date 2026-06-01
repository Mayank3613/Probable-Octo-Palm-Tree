/* ─── INDICATORS OF COMPROMISE (IOC) DATA ───────────────────────────────────
   Static seed data for the Intelligence view.
   In production, replace with an API call to your threat-intel feed.
─────────────────────────────────────────────────────────────────────────── */

const IOC_DATA = {
  ip: [
    { val: '185.220.101.45',  type: 'TOR Exit',  risk: 'critical' },
    { val: '94.102.49.190',   type: 'C2 Server', risk: 'critical' },
    { val: '45.155.205.233',  type: 'Botnet',    risk: 'high'     },
    { val: '193.32.162.190',  type: 'Proxy',     risk: 'high'     },
    { val: '5.188.10.180',    type: 'Scanner',   risk: 'medium'   },
  ],
  domain: [
    { val: 'secure-login.bank-update.net',   type: 'Phishing',           risk: 'critical' },
    { val: 'malware-cdn.darkweb.ru',         type: 'Malware CDN',        risk: 'critical' },
    { val: 'paypal-verify.suspicious.io',    type: 'Credential Harvest', risk: 'high'     },
    { val: 'tracker.ads-pixel.com',          type: 'Tracker',            risk: 'medium'   },
  ],
  hash: [
    { val: 'd41d8cd98f00b204e9800998ecf8427e', type: 'Malware Dropper', risk: 'critical' },
    { val: '098f6bcd4621d373cade4e832627b4f6', type: 'Ransomware',      risk: 'critical' },
    { val: '5d41402abc4b2a76b9719d911017c592', type: 'Adware',          risk: 'high'     },
  ],
};
