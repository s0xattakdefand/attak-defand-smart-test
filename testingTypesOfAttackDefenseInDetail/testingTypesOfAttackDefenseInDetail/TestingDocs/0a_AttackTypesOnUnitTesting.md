| Attack Type                   | Description                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------- |
| **Test Injection**            | Modify or recompile contract with hidden logic to pass tests                     |
| **Role Misconfiguration**     | Bypass test assumptions by impersonating authorized roles (e.g., via `vm.prank`) |
| **Hidden State Drift**        | State is manipulated outside the function being tested                           |
| **False Positive Test Logic** | Unit test always passes due to poor assertion logic                              |
| **Missing Negative Cases**    | No coverage for invalid inputs, allowing security bypass                         |
| **Function Mutation Drift**   | Function signature changes without corresponding test updates                    |
| **Selector Shadowing**        | Reuse of function names with different params to hide behavior                   |
| **Gas-Bomb Passes**           | Malicious logic increases gas usage without causing test failure                 |
