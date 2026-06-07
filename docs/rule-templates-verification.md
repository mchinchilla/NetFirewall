# Manual verification checklist — wizard rule templates

How to verify the "starting rule set" templates on a live firewall. The templates
write **only to the database** (network objects + tagged `fw_*` rows) — nothing
reaches the kernel until you click **Apply** in Firewall. So you can run every
check below before any rule is live, and roll back by clicking "Clear template
rules" or deleting the rows.

> All template-generated rows carry a `[tpl]` description tag; network objects
> carry `[tpl-obj]`. That tag is how idempotency and "clear" stay scoped to the
> template without touching your hand-made rules.

## 0. Pre-req

- Run through wizard Step 1 (assign at least one **WAN** and one **LAN** interface)
  before Step 3 — the generator reads `fw_interfaces` (Type = WAN/LAN). If you
  generate a template with no LAN assigned, you'll see a note saying LAN rules
  were skipped.

## 1. Gateway (NAT) — the common case

In Step 3, pick **Internet gateway (NAT)**, leave NAT + management on, click
**Generate rule set**. Expect a toast like *"Template 'Internet gateway (NAT)'
generated: N rules, M network objects…"*.

Then verify in the DB (or the Firewall UI):

- [ ] **Network objects exist** (Firewall → Network objects, or SQL):
  ```sql
  SELECT name, type, value FROM network_objects WHERE description LIKE '[tpl-obj]%' ORDER BY name;
  ```
  Expect: `LAN_NETWORKS` (group), `RFC1918` (group), `BOGONS` (group),
  `MGMT_SOURCES` (group), plus leaf members (`LAN_<iface>`, `RFC1918_10/172/192`,
  `BOGON_*`).
- [ ] **LAN_NETWORKS group contains your LAN's CIDR**:
  ```sql
  SELECT child.name, child.value
    FROM network_object_members m
    JOIN network_objects parent ON parent.id = m.parent_id
    JOIN network_objects child  ON child.id  = m.child_id
   WHERE parent.name = 'LAN_NETWORKS';
  ```
  Expect a row whose `value` is your LAN /24 (e.g. `192.168.1.0/24`).
- [ ] **Filter rules are tagged + reference objects by NAME** (not raw CIDRs):
  ```sql
  SELECT chain, action, description, source_addresses, destination_ports
    FROM fw_filter_rules WHERE description LIKE '[tpl]%' ORDER BY chain, priority;
  ```
  Expect: input established/related, loopback, drop-invalid; ICMP; SSH(22) +
  web-UI port from `{MGMT_SOURCES}`; DNS from `{LAN_NETWORKS}`; DHCP; forward
  established/related + `{LAN_NETWORKS}` outbound + a default-deny drop at
  priority 9000. Note the `source_addresses` contain object **names**, not CIDRs.
- [ ] **NAT rules use literal LAN CIDRs** (the `source_network` column is a
  Postgres `cidr` type, so it can't hold an object name — expect one masquerade
  row per LAN network per WAN):
  ```sql
  SELECT type, source_network, description FROM fw_nat_rules WHERE description LIKE '[tpl]%';
  ```
  Expect `masquerade`, `source_network` = your LAN /24, out = your WAN.

## 2. Object reference actually resolves

The whole point of object-by-name is that the resolver expands it at apply time.
Confirm the generated rules will produce valid nftables:

- [ ] Firewall → **Apply** (or preview the generated nftables). The
  `{LAN_NETWORKS}` / `{MGMT_SOURCES}` references must expand to your real CIDRs in
  the rendered ruleset — no literal `LAN_NETWORKS` token should appear in
  `nft list ruleset`.
- [ ] After Apply, from a LAN client: outbound internet works (NAT), and the
  firewall answers ping (if ICMP left on) and the web UI on your chosen port.
- [ ] From the WAN side: unsolicited inbound is dropped (default-deny).

## 3. Idempotency — re-generate doesn't duplicate

- [ ] Click **Generate rule set** again (same or different toggles). Expect the
  rule/object counts to stay the same shape — no duplicate `[tpl]` rows:
  ```sql
  SELECT description, count(*) FROM fw_filter_rules WHERE description LIKE '[tpl]%'
   GROUP BY description HAVING count(*) > 1;   -- expect ZERO rows
  ```

## 4. Clear leaves your own rules

- [ ] Add a hand-made rule first (Firewall → Rules → add one, e.g. allow tcp/8443).
- [ ] Generate a template, then click **Clear template rules**. Expect a toast
  *"Removed N template-generated rules"*.
- [ ] Verify your hand-made rule survived and all `[tpl]` rules are gone:
  ```sql
  SELECT count(*) FROM fw_filter_rules WHERE description LIKE '[tpl]%';  -- expect 0
  SELECT description FROM fw_filter_rules WHERE description NOT LIKE '[tpl]%'; -- your rule present
  ```
  (Network objects are intentionally **kept** on clear — they're reusable and may
  be referenced by your own rules.)

## 5. Router (no-NAT) base

- [ ] Pick **Transparent router (no NAT)**, leave NAT checked. Expect a note
  *"NAT requested but base is 'router' — masquerade was skipped"* and:
  ```sql
  SELECT count(*) FROM fw_nat_rules WHERE description LIKE '[tpl]%';  -- expect 0
  SELECT count(*) FROM fw_filter_rules WHERE chain='forward' AND description LIKE '[tpl]%'; -- > 0
  ```

## 6. Bastion base

- [ ] Pick **Bastion / single host**. Expect input-only — no forward rules:
  ```sql
  SELECT count(*) FROM fw_filter_rules WHERE chain='forward' AND description LIKE '[tpl]%'; -- expect 0
  ```

## 7. Multi-WAN (needs 2+ WAN interfaces assigned)

- [ ] With two WANs assigned, enable **Multi-WAN policy routing**. Expect route
  tables + policy rules:
  ```sql
  SELECT table_id, table_name FROM fw_route_tables WHERE description LIKE '[tpl]%';
  SELECT fwmark, table_name FROM fw_policy_rules WHERE description LIKE '[tpl]%';
  ```
  Expect one `wanN` table + one fwmark→table policy rule per WAN. With only one
  WAN, expect a note *"Multi-WAN requested but only 1 WAN assigned — skipped"* and
  zero routing rows.

## 8. UI collapse behavior

- [ ] After **Generate rule set**, the manual baseline toggles below collapse into
  a green "Rule set generated" banner; the Continue button reads
  **"Continue with template"**.
- [ ] Click **Adjust manually** → the manual toggles reappear.
- [ ] Click **Clear template rules** → collapse reverts to the manual baseline.
- [ ] Navigate back to Step 3 (stepper) after generating → it remembers the
  collapsed state (driven by the saved `UsedTemplate` flag).

## 9. Completion doesn't double-generate

This is the subtle one. When a template was used, wizard **Complete** must SKIP
the manual firewall generator (else you'd get a second overlapping CIDR-based
rule set).

- [ ] Generate a template, finish the wizard (Complete). Verify there are **no**
  untagged firewall rules created by completion that duplicate the template's
  intent:
  ```sql
  -- The only firewall rows should be your [tpl] ones (+ any you made by hand).
  SELECT description LIKE '[tpl]%' AS is_template, count(*)
    FROM fw_filter_rules GROUP BY 1;
  ```
  If you instead used the **manual** toggles (no template), Complete SHOULD
  generate the manual rules as before — that path is unchanged.

## Rollback

Everything is DB-only until Apply. To undo a template entirely:
```sql
DELETE FROM fw_filter_rules  WHERE description LIKE '[tpl]%';
DELETE FROM fw_nat_rules     WHERE description LIKE '[tpl]%';
DELETE FROM fw_port_forwards WHERE description LIKE '[tpl]%';
-- objects (optional — safe to keep; remove only if nothing references them):
-- DELETE FROM network_objects WHERE description LIKE '[tpl-obj]%';
```
…or just click **Clear template rules**. Then re-Apply to push the cleaned state.
