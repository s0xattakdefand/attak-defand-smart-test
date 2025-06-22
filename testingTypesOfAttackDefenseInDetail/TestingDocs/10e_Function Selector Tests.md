🧩 Function Selector Tests in Smart Contracts
Function Selector Testing ensures that smart contracts correctly handle, restrict, and route based on the first 4 bytes of calldata (msg.sig), which identify the function being called. This is critical for:

🧠 proxy routing

🛡️ fallback security

🧪 fuzzing resistance

🔐 upgradeable and multicall logic

📡 ABI-level safety in low-level call() operations

📛 Selector mismatch = silent execution of wrong logic or fallback traps.

✅ Types of Function Selector Tests
#	Type	Description
1	Selector Matching Test	Confirm correct selector triggers correct function.
2	Unknown Selector Rejection Test	Ensure unrecognized selectors are rejected via fallback().
3	Fallback Selector Drift Test	Send mutated selectors and ensure fallback doesn’t behave unexpectedly.
4	Proxy Selector Routing Test	Ensure correct logic contract is routed via delegatecall for selector.
5	Multicall Selector Order Test	Validate that each selector in a batch executes the correct subcall.
6	Zombie Selector Replay Test	Test reactivation of old or unused selectors via fallback.
7	Selector Collision Test	Confirm no two functions share the same 4-byte signature.
8	Selector Registration Consistency	Ensure selector list matches ABI or registry (e.g., SelectorRegistry).
9	Dynamic Selector Mapping Test	For routers, ensure dynamic functionId => implementation logic maps correctly.
10	Drifted Calldata Replay Test	Replay low-level calldata with altered inputs to check selector path.

⚔️ Attack Types Detected by Selector Testing
Attack Type	Description
Zombie Function Selector	Old selector not removed, still executable via fallback.
Selector Collision	Two unrelated functions resolve to the same 4-byte selector.
Proxy Drift	Proxy forwards selector to wrong logic contract after upgrade.
Multicall Exploit	Selector injected mid-batch to mutate behavior.
Delegatecall Selector Spoof	Low-level call passes spoofed selector to logic contract.
Fallback Route Activation	Drifted selector enables unintended fallback execution.
Unknown Function Acceptance	Contract accepts and executes unknown calls via call().
Function Hash Hijack	Attacker deploys same selector as target for cross-call abuse.

🛡️ Defense Types Enabled by Selector Testing
#	Defense	Description
✅ Strict Selector Routing	Proxy/router only forwards known selectors.	
✅ Fallback Selector Rejection	Unrecognized msg.sig triggers explicit revert.	
✅ Selector Registry Enforcement	Mapping between function name ↔ selector is canonical.	
✅ Zombie Function Lock	Legacy functions removed from logic contract.	
✅ Multicall Validation	Batch call executes exactly in defined selector order.	
✅ Cross-Chain Selector Safety	Rejects selector mismatches across L1/L2 payloads.	
✅ Upgrade Drift Prevention	Ensures selector mappings preserved post-upgrade.	
✅ ABI Mutation Lock	Contract upgrade can't introduce unexpected selector via ABI mismatch.	

