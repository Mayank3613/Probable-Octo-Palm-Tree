/* ─── CVE DATA ───────────────────────────────────────────────────────────────
   Static seed of tracked CVEs shown in the Intelligence view.
─────────────────────────────────────────────────────────────────────────── */

const CVE_DATA = [
  { id: 'CVE-2024-4577',  score: 9.8,  desc: 'PHP CGI argument injection — critical RCE',          affected: 'PHP < 8.3.8'       },
  { id: 'CVE-2024-21762', score: 9.6,  desc: 'FortiOS out-of-bounds write — unauthenticated RCE',  affected: 'FortiOS 7.x'       },
  { id: 'CVE-2024-3400',  score: 10.0, desc: 'PAN-OS command injection — zero-day',                affected: 'PAN-OS < 11.1.2'   },
  { id: 'CVE-2023-46805', score: 8.2,  desc: 'Ivanti ICS auth bypass',                             affected: 'ICS 9.x/22.x'      },
  { id: 'CVE-2024-1709',  score: 10.0, desc: 'ConnectWise ScreenConnect auth bypass',              affected: '< 23.9.8'          },
];
