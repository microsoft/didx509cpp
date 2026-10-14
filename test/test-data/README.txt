Fulcio and OtherName test data
=============================

Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

fulcio-test-vectors.json contains all 162 vectors whose IDs contain "fulcio" or
"othername", selected without modifying their contents from:

https://github.com/microsoft/did-x509/blob/054f1f6e364580c42fad862747903f2a6ee19976/test-vectors.json

The upstream source file's Git blob SHA is
ff7e21a7aa1e8a21c20fe64dcf2217f7f30c3c58.

To refresh the subset, download the upstream test-vectors.json at the selected
revision and run:

  jq '[.[] | select(.id | test("fulcio|othername"))]' test-vectors.json

The corpus embeds the original certificate chains as base64url-encoded DER,
including the production pydantic-ai 2.54.0 and sigstore-js 2026-08-04 chains and
the legacy staging chain. No certificates are rewritten or re-signed.

Every vector checks path and predicate validation through resolve_chain().
Successful vectors with supported JWK types also check resolve() and resolve_jwk()
against the upstream public keys, while retaining this library's existing DID
Document shape. The upstream synthetic certificates use Ed25519, which this
library does not currently export as a JWK.

fulcio-othername.pem is a separate signed P-256 leaf/root chain that exercises
OtherName predicates through all three public resolution APIs. Its SAN contains
Alice and Bob identities plus a duplicate Alice entry. The leaf has independent,
different legacy and V2 issuers and a Token Subject that differs from its SAN.
The root-only deployment-environment field must never supply a leaf match.
The opaque runner-environment value "opaque%GG" must match "opaque%25GG", but
never a selector containing the malformed escape "opaque%GG".

fulcio-ca-othername-invalid.pem uses the same valid leaf and a separately signed
root certificate with the registered .7 OtherName encoded as an IA5String rather
than a UTF8String. Its X.509 path is valid, but every resolution API must reject
the unselected CA SAN eagerly.

fulcio-othername.cnf contains both fixture profiles. To regenerate the public
fixtures, use an ignored build/fulcio-fixture directory from the repository root:

  mkdir -p build/fulcio-fixture
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out build/fulcio-fixture/root.key
  openssl req -new -x509 -key build/fulcio-fixture/root.key -subj "/CN=didx509cpp OtherName Test Root" -set_serial 1 -days 3650 -config test/test-data/fulcio-othername.cnf -extensions root -out build/fulcio-fixture/root.pem
  openssl req -new -x509 -key build/fulcio-fixture/root.key -subj "/CN=didx509cpp OtherName Test Root" -set_serial 3 -days 3650 -config test/test-data/fulcio-othername.cnf -extensions root-malformed-othername -out build/fulcio-fixture/root-invalid-othername.pem
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out build/fulcio-fixture/leaf.key
  openssl req -new -key build/fulcio-fixture/leaf.key -subj "/CN=didx509cpp OtherName Test Leaf" -out build/fulcio-fixture/leaf.csr
  openssl x509 -req -in build/fulcio-fixture/leaf.csr -CA build/fulcio-fixture/root.pem -CAkey build/fulcio-fixture/root.key -set_serial 2 -days 3650 -extfile test/test-data/fulcio-othername.cnf -extensions leaf -out build/fulcio-fixture/leaf.pem
  cat build/fulcio-fixture/leaf.pem build/fulcio-fixture/root.pem > test/test-data/fulcio-othername.pem
  cat build/fulcio-fixture/leaf.pem build/fulcio-fixture/root-invalid-othername.pem > test/test-data/fulcio-ca-othername-invalid.pem

Remove the generated private keys and intermediate files after regeneration;
only the public certificate bundle belongs in source control.

Additional SAN validation fixtures
---------------------------------

san-scalar-syntax.pem contains a registered username OtherName, literal "%GG"
values in DNS/email/URI SANs, empty SAN scalars, and a URI with a path and query.
The subject CN and legacy issuer also contain a literal "%GG". Valid predicates
encode the percent as "%25"; malformed escapes and empty selectors fail. Raw
slashes/questions in a DID fail, while encoded identity values and fragments
containing those characters remain valid.

san-nonascii-dns.pem, san-nonascii-email.pem, and san-nonascii-uri.pem each contain
a valid username OtherName alongside one IA5 SAN with the invalid byte 0xff.
Their signatures and X.509 paths are valid, but resolution must reject the
malformed entry even when the username predicate matches.

The leaf-scalar-syntax and leaf-nonascii-* profiles in fulcio-othername.cnf encode
these SANs as raw DER so fixture generation does not reject the negative values.
Generate them from the repository root with:

  mkdir -p build/san-review-fixtures
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out build/san-review-fixtures/root.key
  openssl req -new -x509 -key build/san-review-fixtures/root.key -subj "/CN=didx509cpp SAN Review Root" -set_serial 1 -days 3650 -config test/test-data/fulcio-othername.cnf -extensions root -out build/san-review-fixtures/root.pem
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out build/san-review-fixtures/leaf.key
  openssl req -new -key build/san-review-fixtures/leaf.key -subj "/CN=literal%GG" -out build/san-review-fixtures/leaf.csr
  serial=10
  for profile in scalar-syntax nonascii-dns nonascii-email nonascii-uri; do
    openssl x509 -req -in build/san-review-fixtures/leaf.csr -CA build/san-review-fixtures/root.pem -CAkey build/san-review-fixtures/root.key -set_serial "$serial" -days 3650 -extfile test/test-data/fulcio-othername.cnf -extensions "leaf-$profile" -out build/san-review-fixtures/leaf.pem
    cat build/san-review-fixtures/leaf.pem build/san-review-fixtures/root.pem > "test/test-data/san-$profile.pem"
    serial=$((serial + 1))
  done

Remove only the generated keys, CSR, and intermediate PEM files after generation.
