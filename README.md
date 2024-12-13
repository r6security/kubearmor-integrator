<p align="center">
  <img alt="Phoenix", src="docs/img/phoenix-logo.png" width="30%" height="30%"></br>
</p>

# KubeArmor-integrator

> Warning: This project is in active development, consider this before deploying it in a production environment.  All APIs, SDKs, and packages are subject to change.

## Documentation

The KubeArmor-integrator is an integration backend between [KubeArmor](https://kubearmor.io/) and the [Phoenix AMTD Operator](https://github.com/r6security/phoenix). To check what is an integration backend and how it is connected to other modules please consult with [the concepts page in phoenix operator](https://github.com/r6security/phoenix/blob/main/docs/CONCEPTS.md).

This integration is responsible to provide a way to translate KubeArmor alerts to Phoenix SecurityEvents by subscribing KuberArmor alert events. To use this application it requires a KubeArmor instance with a configured KubeArmor Relay Server that is accessible for the running instance of this KubeArmor-integrator.

KubeArmor-integrator requires only one configuration, that is the environment variable `KUBEARMOR_SERVICE` where one can define the endpoint of the KubeArmor Relay Server. The only  The generated SecurityEvent resource will contain 'KubeArmorIntegrator' in the `.spec.rule.source` field. All the other fields are calculated from the given KubeArmor alert structure.

For more details about the Phoenix AMTD operator please visit its [repository](https://github.com/r6security/phoenix/).

## Caveats

* The project is in an early stage where the current focus is to be able to provide a proof-of-concept implementation that a wider range of potential users can try out. We are welcome all feedbacks and ideas as we continuously improve the project and introduc new features.

## Help

Phoenix development is coordinated in Discord, feel free to [join](https://discord.gg/9t8FXumA).

## License

Copyright 2021-2024 by [R6 Security](https://www.r6security.com), Inc. Some rights reserved.

Server Side Public License - see [LICENSE](/LICENSE) for full text.
