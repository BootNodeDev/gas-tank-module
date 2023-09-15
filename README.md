# GasTank Module

The GasTankModule enables the execution of transactions within a Safe without the user having to pay for the gas required for execution. To achieve this, the contract offers two key functionalities:

1. **Transaction Execution:** The GasTankModule facilitates the execution of transactions within a specific Safe. These transactions are initiated using the Gelato relayer, allowing them to be executed without the user being burdened with gas costs.

2. **Gelato Fee Payment:** To cover the fees charged by Gelato for its relayer service, the GasTankModule retrieves the necessary tokens from a Safe designated as the "GasTank". This can be either the same Safe from which the transaction is executed or a different Safe where the GasTankModule acts as a module.

To obtain the required tokens for Gelato fee payment, two options are available:

- **Option 1:** The GasTank is the same Safe from which the transaction is executed. In this case, the user needs to be an owner of that Safe and sign a series of parameters authorizing the payment of fees from the GasTank.

- **Option 2:** The GasTank is a different Safe from the one used for transaction execution. For this option, the user must be previously added as a delegate or be an owner of the GasTank and also authorize the fee payment.

In summary, the GasTankModule provides a solution for covering gas costs associated with transactions within a Safe by getting the tokens to pay for Gelato's relayer service fees from a GasTank. It offers flexibility by allowing the GasTank to be either the same Safe used for execution or a different one, as long as the user meets the authorization requirements.

![diagram](./docs/GasTank.png)

## Installation

_Having issues? See the [troubleshooting section](https://github.com/foundry-rs/foundry/blob/master/README.md#troubleshooting-installation)_.

First run the command below to get `foundryup`, the Foundry toolchain installer:

```sh
curl -L https://foundry.paradigm.xyz | bash
```

If you do not want to use the redirect, feel free to manually download the
foundryup installation script from
[here](https://raw.githubusercontent.com/foundry-rs/foundry/master/foundryup/foundryup).

Then, run `foundryup` in a new terminal session or after reloading your `PATH`.

Other ways to use `foundryup`, and other documentation, can be found [here](https://github.com/foundry-rs/foundry/tree/master/foundryup). Happy forging!

## Install dependencies

### Yarn

```
yarn install
```

### Forge

```
forge install
```

## Run tests

Create an `.env` file using `.env.example` as template, then run

```
yarn test
```

## License

This project is licensed under Business Source License 1.1.
