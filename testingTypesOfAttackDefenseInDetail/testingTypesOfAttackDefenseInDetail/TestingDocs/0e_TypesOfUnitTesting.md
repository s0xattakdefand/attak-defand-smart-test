| Type                         | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| **Positive Tests**           | Ensure functions behave correctly for valid inputs                |
| **Negative Tests**           | Ensure errors are correctly thrown on invalid inputs              |
| **Boundary/Edge Tests**      | Test upper/lower bounds (e.g., overflows, limits, time cutoffs)   |
| **Revert Expectation Tests** | Confirm function reverts on invalid access or logic violation     |
| **Permission Tests**         | Validate only authorized roles/users can call a function          |
| **Gas-Use Assertion Tests**  | Check that gas used remains under a defined limit                 |
| **Storage/State Tests**      | Ensure storage is updated correctly (e.g., after transfers/mints) |
| **Event Emission Tests**     | Confirm proper event logs are emitted during actions              |
| **Constructor Tests**        | Verify initial values after deployment                            |
| **Function Selector Tests**  | Ensure correct dispatching of function selectors                  |
