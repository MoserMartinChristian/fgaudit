# Sources and how they were used

All documents are official Fortinet publications unless noted. They were read in November 2026.
fgaudit is unofficial and not affiliated with or endorsed by Fortinet.

## CLI References (config syntax, field names, defaults)

| Document | Used for |
|---|---|
| [FortiOS 7.4.0 CLI Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/9193cdf6-ef51-11ed-8e6d-fa163e15d75b/FortiOS-7.4.0-CLI_Reference.pdf) | Field names of `firewall policy`, `firewall address/address6/addrgrp`, `firewall service custom/group`, `firewall vip`, `firewall ippool`, `system interface`, `system zone`, `system sdwan`, `system dhcp server`, `vpn ipsec phase1/phase2-interface`, `router static`, `system ha`, `system global`, `system admin`, `firewall local-in-policy`. |
| [FortiOS 7.6.4 CLI Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/0bec1c7c-7948-11f0-9bfd-6af4c3636dc7/FortiOS-7.6.4-CLI_Reference.pdf) | The same sections for 7.6, e.g. `exclude-member` on address groups, the address types (`ipmask`, `iprange`, `fqdn`, `geography`, `wildcard`, `dynamic`, `interface-subnet`, `mac`, `route-tag`), `allow-subnet-overlap`, `vrf` on interfaces. |
| [FortiOS 8.0.2 CLI Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/618862e1-3462-11f1-b31d-02356ffb40d9/FortiOS-8.0.2-CLI_Reference.pdf) | The same sections for 8.0, to confirm that the fields used by the checks still exist. |

## Log References (log IDs, fields, messages)

| Document | Used for |
|---|---|
| [FortiOS 7.4.9 Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/514718ad-8f65-11f0-9bfd-6af4c3636dc7/FortiOS_7.4.9_Log_Reference.pdf) | Log header fields (`date`, `time`, `eventtime`, `tz`, `logid`, `type`, `subtype`, `devname`, `devid`, `vd`), and the event log IDs used by the timeline. |
| [FortiOS 7.6.4 Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/3ac31ccf-6656-11f0-a9d0-d2b0d2e22f7d/FortiOS_7.6.4_Log_Reference.pdf) | Same, for 7.6. |
| [FortiOS 8.0.0 Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/be09e711-381d-11f1-b31d-02356ffb40d9/FortiOS_8.0.0_Log_Reference.pdf) | Same, for 8.0. |

Every log ID in fgaudit's table (`src/fgaudit/checks/timeline.py`, table `MSG`) was checked to be
present in **all three** Log References:

- interface status: 20090, 20099
- BGP and OSPF neighbours: 20300, 20302, 20303
- conserve mode: 22011, 22012, 22802, 22803
- routing and SD-WAN: 22921, 22922, 22923, 22925
- IPsec: 23101, 23102, 37120–37125, 37127–37130, 37137, 37138
- HA: 35011, 35013, 35016, 37892, 37898, 37901, 37902, 37904, 37910
- admin login: 32001, 32002
- config changes: 32102, 32104, 44544–44548
- system events (reboot, shutdown, restart): 32138, 32200, 32545

## Other sources

| Source | Used for |
|---|---|
| [Fortinet Community: Understanding FortiGate configuration file format](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Understanding-FortiGate-Configuration-File-Format/ta-p/373020) | The `#config-version=` header and the overall layout of a backup with and without VDOMs. |
| [fotoobo documentation: FortiGate config](https://fotoobo.readthedocs.io/en/latest/developer/how_to/fortinet/fortigate/fortigate_config.html) (community project, not Fortinet) | Cross-check of the nesting rules (`config`/`edit`/`set`/`next`/`end`) and quoting. |

## Gaps: what the documentation does not say

These points are not documented in the references above. fgaudit handles them heuristically, and
the README says so:

- **Header format.** The `#config-version=MODEL-X.Y.Z-FW-buildNNNN-YYMMDD:opmode=…:vdom=…:user=…`
  line is not specified in the CLI Reference. It is described only in the community article.
- **Encrypted backups.** The file layout of a password-encrypted backup is not documented.
  fgaudit recognises it by a version header followed by binary or base64 data instead of `config`
  blocks.
- **Message text.** The free-text `msg` of some events (interface up/down wording, BGP and OSPF
  neighbour messages) is not given verbatim in the Log Reference. fgaudit relies on the log ID and
  the structured fields first, and on the text only as a fallback. The text patterns follow
  examples from community posts.
- **eventtime unit.** The Log References describe `eventtime` as an epoch timestamp; examples show
  nanoseconds in newer versions. fgaudit detects seconds, milliseconds, microseconds and
  nanoseconds by magnitude.
