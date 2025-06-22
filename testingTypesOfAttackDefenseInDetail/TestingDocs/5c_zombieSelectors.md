🧟‍♂️ Zombie Selectors in Smart Contracts
Zombie Selectors are function selectors (4-byte signatures) that:

✅ Exist in bytecode but have no logic, or

🧟 Used to exist but are no longer connected to any live function (or only accessible via fallback)

🎭 Appear dead to ABIs/static analysis but still trigger exploitable fallback/delegatecall logic

They represent a hidden attack surface, especially in upgradeable contracts, proxies, fallback routers, and calldata-driven systems.

✅ Types of Zombie Selectors
#	Type	Description
1	Orphaned Selectors	Functions removed in upgrade, but selector still mapped in router/proxy.
2	Dead Fallback Selectors	Selectors that hit fallback(), but fallback routes to unintended or legacy logic.
3	Ghost ABI Selectors	Selector exists onchain, but no ABI maps it — invisible to tooling, yet callable.
4	Preimage Drift Selectors	Selectors generated via mutation or fuzzing (e.g. 0x1badface) that map to no known function.
5	Selector Overlaps in Clones	Clones or proxies inherit a selector that executes unexpected logic due to different layout.
6	Retired Upgrade Selectors	Selectors from past implementations still routable via fallback or manual delegatecall.
7	Backdoored Selector Hooks	Selectors only usable by specific caller+calldata combo; hidden from ABI.
8	Calldata-Aligned Zombies	Encoded calldata accidentally maps to zombie logic (e.g., during multicall, execute()).
9	Router Drift Selectors	Router contracts hardcoded with old or mutated selectors (e.g. functionX() => functionY() in upgrade).
10	Re-deployed Selector Resurrection	Contracts with same selector re-deployed to trigger old fallback routes via call.

⚔️ Attack Patterns
Type	Exploit
Ghost ABI	Send direct calldata to unknown function 0xdeadbeef → gets routed via fallback to logic
Preimage Drift	Use fuzzing to discover undocumented selectors that execute legacy logic
Router Drift	execute(bytes calldata) forwards to selector still mapped in outdated logic
Clone Drift	Same selector in different clone yields unexpected result due to layout change
Resurrection	Deploy a contract with a selector that activates legacy delegatecall logic on target

🛡️ Defense Strategies
Type	Defense
Selector Registry	Maintain onchain registry of allowed selectors (and versions)
Fallback Guards	Fallback must revert() on unknown selectors or emit warnings
ABI Drift Monitoring	Monitor deployed contracts for selectors not in current ABI
Fuzz + Replay Gates	Fuzz all reachable selectors, block unregistered replays
Function Selector Hash Verification	Check function hashes via bytes4(keccak256(...)) against approved list