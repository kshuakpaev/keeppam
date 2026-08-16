package keeppam.authz

# Extra deny on top of Go ACL (RBAC/ABAC/JIT/risk). Empty rules = no extra deny.
# OPA never grants access. Admin bypass and break-glass skip this file.
#
# Input (JSON):
#   user.{id,username,roles,tags}
#   asset.{id,name,type,protocol,tags}
#   binding.{id,max_risk,risk_action,allowed_namespaces,group_id,tag_acl,asset_match_tags,http_policy_pack_id,app_object_pack_id}
#   request.{ticket_id,reason,client_ip,client_country,client_devices,risk_score,risk_factors}
#
# Query: data.keeppam.authz.deny
#   set of messages → deny; empty/undefined → allow
#   or boolean deny
#
# Examples (uncomment):
#
# deny[msg] {
#   input.asset.protocol == "kubectl"
#   input.request.ticket_id == ""
#   msg := "kubectl requires ticket_id"
# }
#
# deny[msg] {
#   input.request.client_country == "CN"
#   msg := "country blocked by opa"
# }
