#!/usr/bin/env bash
# Static checks that `terraform test` assertions cannot express:
#   S1  resource inventory matches the approved design exactly (no unwanted resources)
#   S2  forbidden resource types are absent
#   S3  no external IP, primitive roles or private-key inputs in the module
#   S4  the only 0.0.0.0/0 source is the logged deny-all rule
#   S5  explicit VM -> Cloud NAT dependency edge exists in `terraform graph`
#   S6  no credential-like content in any task file
#
# Offline. Needs `terraform init -backend=false` to have run (S5 loads the
# provider schema). Usage (from task-01-gcp-terraform/): bash tests/static_checks.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }

# S1 ------------------------------------------------------------------------
expected_inventory='google_compute_backend_service.this
google_compute_firewall.allow_lb_to_backend_http
google_compute_firewall.allow_ssh_trusted
google_compute_firewall.deny_all_ingress
google_compute_global_address.this
google_compute_global_forwarding_rule.https
google_compute_health_check.http
google_compute_instance.this
google_compute_instance_group.this
google_compute_instance_iam_member.os_login
google_compute_managed_ssl_certificate.this
google_compute_network.this
google_compute_router.nat
google_compute_router_nat.this
google_compute_ssl_policy.this
google_compute_subnetwork.private
google_compute_subnetwork.public
google_compute_target_https_proxy.this
google_compute_url_map.this
google_iap_tunnel_instance_iam_member.ssh
google_project_iam_member.vm
google_service_account.vm
google_service_account_iam_member.ssh_admin_sa_user'
actual_inventory="$(sed -nE 's/^resource "([a-z0-9_]+)" "([a-z0-9_]+)".*/\1.\2/p' ./*.tf | LC_ALL=C sort)"
if [[ "$actual_inventory" == "$expected_inventory" ]]; then
  ok "S1 resource inventory matches DESIGN.md (23 resource blocks)"
else
  bad "S1 resource inventory differs from DESIGN.md"
  diff <(echo "$expected_inventory") <(echo "$actual_inventory") | sed 's/^/       /'
fi
if [[ -z "$(sed -nE 's/^data "([a-z0-9_]+)".*/\1/p' ./*.tf)" ]]; then
  ok "S1 no data sources (no live lookups)"
else
  bad "S1 data sources present"
fi

# S2 ------------------------------------------------------------------------
for t in google_service_account_key google_compute_ssl_certificate google_compute_target_http_proxy \
  google_compute_address google_compute_route google_project_iam_binding google_project_iam_policy \
  google_compute_instance_template google_compute_instance_group_manager; do
  if grep -qE "^resource \"$t\"" ./*.tf; then bad "S2 forbidden resource type $t"; else ok "S2 no $t"; fi
done
fr_count="$(grep -cE '^resource "google_compute_global_forwarding_rule"' ./*.tf | awk -F: '{s+=$2} END {print s}')"
if [[ "$fr_count" -eq 1 ]]; then
  ok "S2 exactly one forwarding rule (443)"
else
  bad "S2 expected one forwarding rule, found $fr_count"
fi

# S3 ------------------------------------------------------------------------
code_only() { grep -hvE '^[[:space:]]*#' ./*.tf; }
if code_only | grep -qE '^[[:space:]]*access_config[[:space:]]*\{'; then
  bad "S3 access_config block present (external IP)"
else
  ok "S3 no access_config (no external IP)"
fi
if code_only | grep -qE '"roles/(owner|editor)"[[:space:]]*$'; then
  bad "S3 primitive role granted"
else
  ok "S3 no owner/editor role grants"
fi
if code_only | grep -qiE '^[[:space:]]*(private_key|certificate)[[:space:]]*='; then
  bad "S3 private key / PEM input present"
else
  ok "S3 no private key or PEM certificate inputs"
fi

# S4 ------------------------------------------------------------------------
world_lines="$(code_only | grep -cE 'source_ranges[[:space:]]*=.*0\.0\.0\.0/0' || true)"
deny_block="$(awk '/^resource "google_compute_firewall" "deny_all_ingress"/,/^}/' firewall.tf)"
if [[ "$world_lines" -eq 1 ]] && grep -q '0.0.0.0/0' <<<"$deny_block" && grep -q 'deny {' <<<"$deny_block"; then
  ok "S4 0.0.0.0/0 is used only by the deny-all rule"
else
  bad "S4 unexpected 0.0.0.0/0 source (count=$world_lines)"
fi

# S5 ------------------------------------------------------------------------
if graph="$(terraform graph 2>/dev/null)"; then
  if grep -qE '"(\[root\] )?google_compute_instance\.this( \(expand\))?" -> "(\[root\] )?google_compute_router_nat\.this( \(expand\))?"' <<<"$graph"; then
    ok "S5 graph edge google_compute_instance.this -> google_compute_router_nat.this"
  else
    bad "S5 missing dependency edge VM -> Cloud NAT"
  fi
else
  bad "S5 terraform graph failed (run terraform init -backend=false first)"
fi

# S6 ------------------------------------------------------------------------
secret_re='(BEGIN [A-Z ]*PRIVATE KEY|"private_key_id"|"type":[[:space:]]*"service_account"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+)'
hits="$(grep -rlEI --exclude-dir=.terraform --exclude=static_checks.sh "$secret_re" . || true)"
if [[ -z "$hits" ]]; then
  ok "S6 no credential-like content in task files"
else
  bad "S6 credential-like content in: $hits"
fi

echo
echo "static checks: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
