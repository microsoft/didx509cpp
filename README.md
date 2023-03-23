# didx509cpp

A header-only C++ library for verification of [did:x509](https://github.com/microsoft/did-x509) identifiers.

[![Continuous Integration](https://github.com/microsoft/didx509cpp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/microsoft/didx509cpp/actions/workflows/ci.yml) [![CodeQL](https://github.com/microsoft/didx509cpp/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/microsoft/didx509cpp/actions/workflows/codeql-analysis.yml)

## Usage

```cpp
#include <didx509cpp.h>

std::string pem_chain = ...;
std::string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13";

try {
    std::string doc = resolve(pem_chain, did));
} catch (...)
{...}
    
// Or when resolving a historical did, for example for audit purposes
    
try {
    std::string doc = resolve(pem_chain, did, true /* Ignore time */));
} catch (...)
{...}
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
