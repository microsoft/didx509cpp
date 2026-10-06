# didx509cpp

A header-only C++ library for verification of [did:x509](https://github.com/microsoft/did-x509) identifiers.
The method is [registered within the W3C DID Extensions registry](https://github.com/w3c/did-extensions/blob/main/methods/x509.json) and listed in the [W3C DID Extensions Methods registry](https://www.w3.org/TR/did-extensions-methods/).

[![Continuous Integration](https://github.com/microsoft/didx509cpp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/microsoft/didx509cpp/actions/workflows/ci.yml) [![CodeQL](https://github.com/microsoft/didx509cpp/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/microsoft/didx509cpp/actions/workflows/codeql-analysis.yml)

## Usage

```cpp
#include <didx509cpp.h>

std::string pem_chain = ...;
std::string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13";

try {
    std::string doc = resolve(pem_chain, did);
} catch (...)
{...}
    
// Or when resolving a historical did, for example for audit purposes
    
try {
    std::string doc = resolve(pem_chain, did, true /* Ignore time */));
} catch (...)
{...}
```

## Fulcio identities

The method-version-`0` `fulcio` predicate selects a registered standalone
Fulcio extension on the leaf certificate. For Issuer V2 (`1.3.6.1.4.1.57264.1.8`),
use the full percent-encoded issuer, including its scheme:

```text
::fulcio:issuer:https%3A%2F%2Ftoken.actions.githubusercontent.com
```

All 17 [registered fields](https://github.com/microsoft/did-x509/blob/main/specification.md#standalone-fulcio-extension-registry)
are supported, including source/build metadata, `deployment-environment`, and
`token-subject`. Each predicate requires exactly one literal field and one
nonempty percent-encoded UTF-8 value. Multiple predicates are ANDed.

Fulcio username identities use the registered OtherName type inside the SAN
extension, independently of standalone Fulcio extensions:

```text
::san:othername:1.3.6.1.4.1.57264.1.7:alice%21example.com
```

The type OID must be literal, and the complete username SAN (`alice!example.com`
here) is compared exactly, not reconstructed from `token-subject`. Scalar values
are decoded once, without case folding, URI rewriting, or Unicode normalization.

The existing `fulcio-issuer` predicate still selects only the legacy raw UTF-8
extension `.1`, with `https://` omitted from the predicate value. It never falls
back to `.8`, and `fulcio:issuer` never falls back to `.1`. Existing DID Document
and JWK formats are unchanged. DID URL fragments are excluded from predicate
matching and document IDs; percent-escape spelling in the DID is preserved.

Registered OtherName values and standalone `.8`-`.24` extensions require a
complete, minimally encoded DER UTF8String. Malformed or unsupported SAN entries
and malformed registered Fulcio extensions fail resolution even when unselected
or present on a CA certificate. Standalone Fulcio extensions must be noncritical;
normal certificate path validation is not bypassed.

## Contributing

To run clang-tidy locally, configure with Clang 18 and enable the opt-in
target:

```bash
cmake -S . -B build/clang-tidy \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCLANG_TIDY=ON \
  -DTESTS=ON
cmake --build build/clang-tidy --target clang-tidy
```

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
