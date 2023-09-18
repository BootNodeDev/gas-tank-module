# GasTank Module

The **GasTank Module*** enables the execution of transactions within a Safe without the user having to pay for the gas required for execution. To achieve this, the contract offers two key functionalities:

1. **Transaction Execution:** The **GasTank Module*** facilitates the execution of transactions within a specific Safe. These transactions are initiated using the Gelato relayer, allowing them to be executed without the user being burdened with gas costs.

2. **Gelato Fee Payment:** To cover the fees charged by Gelato for its relayer service, the **GasTank Module*** retrieves the necessary tokens from a Safe designated as the "GasTank". This can be either the same Safe from which the transaction is executed or a different Safe where the **GasTank Module*** acts as a module.

To obtain the required tokens for Gelato fee payment, two options are available:

- **Option 1:** The GasTank is the same Safe from which the transaction is executed. In this case, the user needs to be an owner of that Safe and sign a series of parameters authorizing the payment of fees from the GasTank.

- **Option 2:** The GasTank is a different Safe from the one used for transaction execution. For this option, the user must be previously added as a delegate or be an owner of the GasTank and also authorize the fee payment.

In summary, the **GasTank Module*** provides a solution for covering gas costs associated with transactions within a Safe by getting the tokens to pay for Gelato's relayer service fees from a GasTank. It offers flexibility by allowing the GasTank to be either the same Safe used for execution or a different one, as long as the user meets the authorization requirements.

The contract is designed as a singleton. This way not every Safe needs to deploy their own module and it is possible that this module is shared between different Safes.

![diagram](./docs/GasTank.png)

## Authentication and Authorization
In order to authenticate the sender and validate the authorization to pay the fees, two signatures are required.

1. Is [required by Gelato](https://docs.gelato.network/developer-services/relay/erc-2771-recommended#rationale) in order to authenticate the sender of the relayed transaction, which then is appended to the calldata passed to the module.

2. Is the one used in this module to validate that the sender is whether an owner or a delegate of the GasTank and that it authorize to pay the fees using a given token and up to a maximum amount. For this the module relies in the ERC-721 signature and uses the following schema:

- EIP721Domain
```
{
  EIP712Domain: [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' }
  ]
}
```
- AllowedFee
```
{
  AllowedFee: [
        { name: 'gasTank', type: 'address' },
        { name: 'token', type: 'address' },
        { name: 'maxFee', type: 'uint256' },
        { name: 'nonce', type: 'uint16' }
    ]
}
```
## Setting a Delegate
In order to authorize a non-owner to use a GasTank (a Safe) to pay for transaction of a different Safe, the non-owner account must be set as a `delegate` of the GasTank and indicate which token this new delegate is allowed to use.

For this the following steps should be followed:
1. Enable the **GasTank Module** on the GasTank.
2. Call the `GasTankModule.addDelegate(address _delegate)` from GasTank.
3. Call the `GasTankModule.addTokenAllowance(address _delegate, address _token)` from the GasTank, for each token the given delegate is allowed to use

## Networks
The module would be available on the same address for all the networks where [Gelato is](https://docs.gelato.network/developer-services/relay/networks-and-rate-limits) and also the Safe.

`GasTankModule address: 0x150EfE6b6E093D625313cAe5E7083a4C57fb9BA0`

## Development

### Install Foundry

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

### Install dependencies

#### Yarn

```
yarn install
```

#### Forge

```
forge install
```

### Run tests

Create an `.env` file using `.env.example` as template, then run

```
yarn test
```

## License

This project is licensed under Business Source License 1.1.
