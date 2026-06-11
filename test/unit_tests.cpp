// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "didx509cpp.h"

#include <string>

#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest.h"
#include "json.hpp"

using namespace didx509;

static std::string test_data_dir = "../test/test-data";

static std::string load_certificate_chain(const std::string& path)
{
  std::ifstream t(test_data_dir + "/" + path);
  if (!t.good())
    throw std::runtime_error(std::string("could not open ") + path);
  std::stringstream ss;
  ss << t.rdbuf();
  return ss.str();
}

static std::vector<std::string> split_x509_cert_bundle(
  const std::string_view& pem)
{
  std::string separator("-----END CERTIFICATE-----");
  std::vector<std::string> pems;
  size_t separator_end = 0;
  auto next_separator_start = pem.find(separator);
  while (next_separator_start != std::string_view::npos)
  {
    // Trim whitespace between certificates
    while (separator_end < next_separator_start &&
            (std::isspace(pem[separator_end]) != 0))
    {
      ++separator_end;
    }
    pems.emplace_back(std::string(pem.substr(
      separator_end,
      (next_separator_start - separator_end) + separator.size())));
    separator_end = next_separator_start + separator.size();
    next_separator_start = pem.find(separator, separator_end);
  }
  return pems;
}

void test_resolve_success(const std::string& chain, const std::string& did)
{
  std::string did_doc;
  REQUIRE_NOTHROW(did_doc = resolve(chain, did, true));
  // Verify that resolved DID document is valid JSON
  nlohmann::json doc;
  REQUIRE_NOTHROW(doc = nlohmann::json::parse(did_doc));
  CHECK(doc["@context"] == "https://www.w3.org/ns/did/v1");
  CHECK(doc["id"] == did);
  REQUIRE(doc["verificationMethod"].is_array());
  REQUIRE(doc["verificationMethod"].size() == 1);
  CHECK(doc["verificationMethod"][0]["id"] == did + "#key-1");
  CHECK(doc["verificationMethod"][0]["type"] == "JsonWebKey2020");
  CHECK(doc["verificationMethod"][0]["controller"] == did);
  CHECK(doc["verificationMethod"][0]["publicKeyJwk"].contains("kty"));
  
  std::string jwk;
  const auto split_chain = split_x509_cert_bundle(chain);
  REQUIRE_NOTHROW(jwk = resolve_jwk(split_chain, did, true));
  // Verify that resolved JWK is valid JSON
  nlohmann::json jwk_doc;
  REQUIRE_NOTHROW(jwk_doc = nlohmann::json::parse(jwk));
  CHECK(jwk_doc.contains("kty"));
}

void test_resolve_error(
  const std::string& chain,
  const std::string& did,
  const doctest::String& error_msg)
{
  REQUIRE_THROWS_WITH(resolve(chain, did, true), doctest::Contains(error_msg));
}

void test_resolve_jwk_error(
  const std::vector<std::string>& chain,
  const std::string& did,
  const doctest::String& error_msg)
{
  REQUIRE_THROWS_WITH(resolve_jwk(chain, did, true), doctest::Contains(error_msg));
}

TEST_CASE("Wrong prefix")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did = "djd:y508:1:abcd::";
  test_resolve_error(chain, did, "unsupported method/prefix");
}

TEST_CASE("Empty chain")
{
  auto chain = "";
  auto did = "djd:y508:1:abcd::";
  test_resolve_error(chain, did, "no certificate chain");
}

TEST_CASE("Chain of one not-a-cert-but-a-chain")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_jwk_error({chain}, did, "expected exactly one PEM element");
}

TEST_CASE("Invalid input")
{
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_jwk_error({"-----BEGIN CERTIFICATE-----"}, did, "bad end line");
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto split_chain = split_x509_cert_bundle(chain);
  split_chain[0][42] += 5;
  test_resolve_jwk_error(split_chain, did, "bad base64 decode");
  split_chain[0][42] -= 10;
  test_resolve_jwk_error(split_chain, did, "asn1 encoding routines::too long");
}

TEST_CASE("TestRootCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_success(chain, did);
}

TEST_CASE("TestIntermediateCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:VtqHIq_ZQGb_4eRZVHOkhUiSuEOggn1T-32PSu7R4Ys"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_success(chain, did);
}

TEST_CASE("TestInvalidLeafCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did = "did:x509:0:sha256:h::subject:CN:Microsoft%20Corporation";
  test_resolve_error(chain, did, "invalid certificate fingerprint");
}

TEST_CASE("TestInvalidCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did = "did:x509:0:sha256:abc::CN:Microsoft%20Corporation";
  test_resolve_error(chain, did, "invalid certificate fingerprint");
}

TEST_CASE("TestFingerprintAlgorithms")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha384:tg8BQvQznAnlqwHWedNqMSKxsf-_dDmEB7qsgYP0eamWeA5M5UNdgPQWMtCdWkoz"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_success(chain, did);

  did =
    "did:x509:0:sha512:Lr_EwX4kGmZfVYvMsDil-xCnPgXbVSox4_Dq5IqTyWF9Kklo952md9y82x16FAvphIqromFhlI19tEtOq7sHYw"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_success(chain, did);
}

TEST_CASE("TestUnsupportedFingerprintAlgorithm")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha1:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_error(chain, did, "unsupported fingerprint algorithm");
}

TEST_CASE("TestMultiplePolicies")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.5.5.7.3.3"
    "::eku:1.3.6.1.4.1.311.10.3.21";
  test_resolve_success(chain, did);
}

TEST_CASE("TestSubject")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_success(chain, did);
}

TEST_CASE("TestSubjectWithStateST")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:ST:Washington";
  test_resolve_success(chain, did);
  chain = load_certificate_chain("ms-test.pem");
  did =
    "did:x509:0:sha256:m9D3z27ZZ1GTkbzUmpWIZ7lVpg8i3luJeEdKL8utgaY"
    "::subject:C:US:ST:Washington:L:Redmond:O:Microsoft%20"
    "Corporation:CN:Code%20Sign%20Test%20%28DO%20NOT%20TRUST%29";
  test_resolve_success(chain, did);
}

TEST_CASE("TestSubjectWithStateS")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:S:Washington";
  test_resolve_success(chain, did);
  chain = load_certificate_chain("ms-test.pem");
  did =
    "did:x509:0:sha256:m9D3z27ZZ1GTkbzUmpWIZ7lVpg8i3luJeEdKL8utgaY"
    "::subject:C:US:S:Washington:L:Redmond:O:Microsoft%20"
    "Corporation:CN:Code%20Sign%20Test%20%28DO%20NOT%20TRUST%29";
  test_resolve_success(chain, did);
}

TEST_CASE("TestSubjectWithStateSandST")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:S:Washington:ST:Washington";
  test_resolve_error(chain, did, "duplicate field 'ST'");
  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:ST:Washington:S:Washington";
  test_resolve_error(chain, did, "duplicate field 'ST'");
}

TEST_CASE("TestSubjectInvalidName")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:MicrosoftCorporation";
  test_resolve_error(chain, did, "invalid subject key/value");
}

TEST_CASE("TestSubjectDuplicateField")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:CN:Microsoft%20Corporation";
  test_resolve_error(chain, did, "duplicate field");
}

TEST_CASE("TestDIDParserErrors")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did = "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE";
  test_resolve_error(chain, did, "invalid DID string");

  did =
    "did:x509:1:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  test_resolve_error(chain, did, "unsupported did:x509 version");

  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject";
  test_resolve_error(chain, did, "invalid policy");

  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN";
  test_resolve_error(chain, did, "key-value pairs required");

  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:DC:example";
  test_resolve_error(chain, did, "unsupported subject key");

  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::san:email";
  test_resolve_error(chain, did, "exactly one SAN type and value required");

  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.2.3:1.2.4";
  test_resolve_error(chain, did, "exactly one EKU required");

  did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::fulcio-issuer:issuer:extra";
  test_resolve_error(chain, did, "excessive arguments to fulcio-issuer");
}

TEST_CASE("TestSAN")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  auto did =
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::san:email:igarcia%40suse.com";
  test_resolve_success(chain, did);
}

TEST_CASE("TestSANInvalidType")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  auto did =
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::san:uri:igarcia%40suse.com";
  test_resolve_error(chain, did, "SAN not found");
}

TEST_CASE("TestSANInvalidValue")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  auto did =
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::email:bob%40example.com";
  test_resolve_error(chain, did, "unsupported did:x509 scheme");
}

TEST_CASE("TestSANWithDns")
{
  auto chain = load_certificate_chain("dns-san.pem");
  auto did =
    "did:x509:0:sha256:T1HzOxsDN5SKU6VYKcUFzNVlWiLdxbJ4H7w5WuYcUkM"
    "::san:dns:san-test.example.com";
  test_resolve_success(chain, did);
}

TEST_CASE("TestSANWithIpAddressRejected")
{
  auto chain = load_certificate_chain("dns-san.pem");
  auto did =
    "did:x509:0:sha256:T1HzOxsDN5SKU6VYKcUFzNVlWiLdxbJ4H7w5WuYcUkM"
    "::san:ipaddress:127.0.0.1";
  test_resolve_error(chain, did, "unknown SAN type: ipaddress");
}

TEST_CASE("TestSANUnknownType")
{
  auto chain = load_certificate_chain("dns-san.pem");
  auto did =
    "did:x509:0:sha256:T1HzOxsDN5SKU6VYKcUFzNVlWiLdxbJ4H7w5WuYcUkM"
    "::san:other:value";
  test_resolve_error(chain, did, "unknown SAN type");
}

TEST_CASE("TestBadEKU")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.5.5.7.3.12";
  test_resolve_error(chain, did, "EKU not found");
}

TEST_CASE("TestGoodEKU")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.4.1.311.10.3.21";
  test_resolve_success(chain, did);
}

TEST_CASE("TestEKUInvalidValue")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.2.3";
  test_resolve_error(chain, did, "EKU not found");
}

TEST_CASE("TestFulcioIssuerWithEmailSAN")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  auto did =
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:github.com%2Flogin%2Foauth"
    "::san:email:igarcia%40suse.com";
  test_resolve_success(chain, did);
}

TEST_CASE("TestFulcioIssuerWithURISAN")
{
  auto chain = load_certificate_chain("fulcio-github-actions.pem");
  auto did =
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:token.actions.githubusercontent.com"
    "::san:uri:https%3A%2F%2Fgithub.com%2Fbrendancassells%2Fmcw-continuous-"
    "delivery-lab-files%2F.github%2Fworkflows%2Ffabrikam-web.yml%40refs%"
    "2Fheads%2Fmain";
  test_resolve_success(chain, did);
}

TEST_CASE("TestInvalidFulcioIssuer")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  auto did =
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:example.com"
    "::san:email:igarcia%40suse.com";
  test_resolve_error(chain, did, "invalid fulcio-issuer");
}

TEST_CASE("TestDIDDocumentKeyUsageSections")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  std::string did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  auto doc = nlohmann::json::parse(resolve(chain, did, true));
  CHECK(doc["assertionMethod"] == did + "#key-1");
  CHECK(doc["keyAgreement"] == did + "#key-1");

  chain = load_certificate_chain("dns-san.pem");
  did =
    "did:x509:0:sha256:T1HzOxsDN5SKU6VYKcUFzNVlWiLdxbJ4H7w5WuYcUkM"
    "::san:dns:san-test.example.com";
  doc = nlohmann::json::parse(resolve(chain, did, true));
  CHECK(doc["assertionMethod"] == did + "#key-1");
  CHECK_FALSE(doc.contains("keyAgreement"));
}

TEST_CASE("TestResolveChainDirectly")
{
  auto chain_pem = load_certificate_chain("ms-code-signing.pem");
  UqSTACK_OF_X509 chain(chain_pem);
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation";
  auto valid_chain = resolve_chain(chain, did, true);
  CHECK(valid_chain.size() == 3);
  CHECK(nlohmann::json::parse(valid_chain.front().public_jwk()).contains("kty"));
}

TEST_CASE("TestVerifyHonorsProvidedRoots")
{
  // verify() must anchor trust on the roots it is given, not on the chain's
  // own last certificate. The loop previously added back() (the chain's last
  // certificate) for every entry in `roots`, ignoring the provided roots.
  UqSTACK_OF_X509 chain(load_certificate_chain("ms-code-signing.pem"));

  // A certificate from an unrelated chain that signed nothing in `chain`.
  UqSTACK_OF_X509 unrelated(load_certificate_chain("fulcio-email.pem"));
  std::vector<UqX509> roots;
  roots.emplace_back(unrelated.back());

  // With trust anchored only on the unrelated root, there is no valid path, so
  // verification must fail. The previous code ignored `roots` and trusted
  // chain.back(), which made this wrongly succeed.
  REQUIRE_THROWS_WITH(
    (void)chain.verify(roots, true),
    doctest::Contains("certificate chain verification failed"));
}

TEST_CASE("TestInvalidLeafOnly")
{
  auto chain = load_certificate_chain("containerplat-leaf.pem");
  REQUIRE_THROWS_WITH(
    resolve(
      chain,
      "did:x509:0:sha256:pDI-AL3g4rw3cHMC_dmMKpdzFF8JMFzWvfIzbK9_DbQ"
      "::eku:1.3.6.1.4.1.311.76.59.1.2",
      true),
    doctest::Contains("certificate chain too short"));
}

int main(int argc, char** argv)
{
  doctest::Context ctx;
  ctx.applyCommandLine(argc, argv);
  for (size_t i = 0; i < argc; i++)
    if (i < argc - 1 && strcmp(argv[i], "--data-dir") == 0)
      test_data_dir = argv[i + 1];
  return ctx.run();
}
