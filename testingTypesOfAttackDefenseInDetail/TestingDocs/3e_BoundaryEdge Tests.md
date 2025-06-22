🎯 Boundary / Edge Case Tests in Smart Contracts
Boundary Testing (aka Edge Case Testing) ensures that your contract behaves correctly at the extremes of valid input ranges, helping detect:

🎯 off-by-one errors

🎯 overflows / underflows

🎯 input/output drift near limits

🎯 logic inversion near bounds

⚠️ Many real-world smart contract bugs (e.g., Overflow, UUPS upgrade drift, undercollateralization, missed claim windows) happen at the edge — not in the middle.

✅ Types of Boundary / Edge Case Testing
#	Type	Description
1	Lower Bound Test	Test function with minimum valid input (e.g., 0, 1, or address(0)).
2	Upper Bound Test	Test with maximum valid input (e.g., 2**256 - 1, array.length - 1).
3	Off-By-One Test	Test exactly 1 above/below a critical threshold (==, >=, <).
4	Overflow/Underflow Simulation	Force math to reach uint256 wrap-around limits.
5	Precision Loss Test	Input/output at high precision, small deltas, or decimals.
6	Array Index Edge Test	Access first and last elements, or test array with length = 0.
7	Gas Limit Edge Test	Send inputs that push gas to near-block limit.
8	Block / Timestamp Drift	Call logic at exact open/close time, then just before/after.
9	Balance Threshold Tests	Send just enough/just too little value to see if pass/fail.
10	Selector/Calldata Length Bounds	Fuzz selector with lengths 0, 4, 32, 256 bytes.

⚔️ Attack Types Caught by Boundary Testing
Attack Type	Description
Off-by-One Logic Bug	Reward eligibility at >= vs > fails silently.
Overflow Exploit	a + b exceeds type(uint256).max and wraps to 0.
Underflow Attack	Subtracting more than available causes wrap.
Zero Input Drift	deposit(0) passes validation and alters state incorrectly.
Max Value Trigger	2**256-1 sent to logic causes fee or math misbehavior.
Block Drift Exploit	Time-sensitive logic called just before window opens.
Length Drift	Arrays or bytes are indexed outside bounds.
Gas Bomb Edge	Contract hangs on upper-range loop from near-limit calldata.

🛡️ Defense Types Validated by Boundary Testing
#	Defense Type	Description
✅ SafeMath or Unchecked Zones	Catches if unchecked allows drift or corruption.	
✅ Min/Max Input Validators	Detects missing checks like require(x > 0) or x < max.	
✅ Strict Time Range Enforcers	Validates block.timestamp >= start && <= end logic.	
✅ Loop Capping	Ensures bounded loop iterations from user input.	
✅ State Invariant Anchors	Confirms sum, balances, or thresholds remain within range.	
✅ Zero Value Rejectors	Prevent zero address or zero token from drifting state.	
✅ Event-State Sync Testers	Emits correct values even at boundary triggers.	