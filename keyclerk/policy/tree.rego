# What a viewer may see of the delegation tree (decision 0009, D7 and D8). The engine evaluates it compiled to
# WebAssembly (keyclerk.policy_wasm); code gathers the facts, this file decides. Need to know: a viewer and the root see
# the whole tree. Anyone else sees the delegations they hold or held, everything handed on below them, and the chain
# above them back to the root (who gave them their authority), but not their siblings or what others handed on.
#
# input.viewer: {all, held: [delegation id]}
# input.nodes:  [{id, chain: [id, ...]}]: chain runs from the node itself up to "root"
package keyclerk.tree

import rego.v1

v := input.viewer

held_nodes contains m if {
	some m in input.nodes
	m.id in v.held
}

# mine, or handed on below one of mine
visible(n) if {
	some d in n.chain
	d in v.held
}

# the chain above one of mine
visible(n) if {
	some m in held_nodes
	n.id in m.chain
}

shown contains n.id if {
	some n in input.nodes
	visible(n)
}

every_id contains n.id if some n in input.nodes

decision := {"nodes": sort(every_id), "whole": true} if v.all == true

else := {"nodes": sort(shown), "whole": false}
