// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "didx509cpp.h"

#include <openssl/evp.h>

#include <algorithm>
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

TEST_CASE("TestSubjectExactMatchRequired")
{
  // The subject policy must match attribute values exactly (the spec defines
  // matching via object.subset, i.e. equality), never as a substring. The
  // leaf certificate's CN and O are both "Microsoft Corporation"; no proper
  // substring, prefix or suffix of those values may satisfy the policy.
  auto chain = load_certificate_chain("ms-code-signing.pem");
  const std::string base =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE";

  // Prefix substring of CN.
  test_resolve_error(
    chain, base + "::subject:CN:Microsoft", "invalid subject key/value");
  // Single-character substring of CN.
  test_resolve_error(
    chain, base + "::subject:CN:M", "invalid subject key/value");
  // Suffix substring of CN.
  test_resolve_error(
    chain, base + "::subject:CN:Corporation", "invalid subject key/value");
  // Interior substring of CN (with the space percent-encoded).
  test_resolve_error(
    chain, base + "::subject:CN:soft%20Corp", "invalid subject key/value");
  // Substring of the O attribute.
  test_resolve_error(
    chain, base + "::subject:O:Micro", "invalid subject key/value");

  // The exact, complete value still resolves.
  test_resolve_success(
    chain, base + "::subject:CN:Microsoft%20Corporation");
}

TEST_CASE("TestSubjectUtf8Value")
{
  // The leaf certificate in this chain has a non-ASCII subject value,
  // O="café Ltd", encoded as a UTF8String. The value must be decoded as
  // UTF-8 and compared exactly. Before the UTF-8 fix the value was rendered
  // lossily (the multi-byte "é" became "..") so the exact match below would
  // have been (incorrectly) rejected.
  auto chain = load_certificate_chain("utf8-subject.pem");
  const std::string base =
    "did:x509:0:sha256:gq-05smrC6JilYZzYHrr7SOs3V_y_I4K6JMW3arCL2I";

  // Exact UTF-8 value (percent-encoded "café Ltd") resolves.
  test_resolve_success(chain, base + "::subject:O:caf%C3%A9%20Ltd");

  // A multi-byte-aware prefix substring of the value must be rejected, which
  // also confirms exact matching works correctly for non-ASCII values.
  test_resolve_error(
    chain, base + "::subject:O:caf%C3%A9", "invalid subject key/value");

  // The ASCII CN matches exactly.
  test_resolve_success(
    chain, base + "::subject:CN:didx509cpp%20UTF8%20Test%20Leaf");
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

TEST_CASE("TestSANDnsWildcardNotExpanded")
{
  // The san policy must match SAN entries literally. A wildcard dNSName in the
  // certificate must not be expanded to match a specific host (X509_check_host
  // would otherwise match "evil.example.com" against a "*.example.com" SAN).
  auto chain = load_certificate_chain("wildcard-dns-san.pem");
  const std::string base =
    "did:x509:0:sha256:oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8";

  // A specific host must not match the wildcard SAN.
  test_resolve_error(
    chain, base + "::san:dns:evil.example.com", "SAN not found");

  // The literal wildcard value (percent-encoded '*') matches exactly.
  test_resolve_success(chain, base + "::san:dns:%2A.example.com");
}

TEST_CASE("TestSANUriEmbeddedNulNotTruncated")
{
  // The leaf has a uniformResourceIdentifier SAN whose value contains an
  // embedded NUL byte: "https://trusted.example\0.attacker.test". The value
  // must be compared using its explicit length so that the NUL cannot be used
  // to spoof a prefix of a pinned value.
  auto chain = load_certificate_chain("uri-san-embedded-nul.pem");
  const std::string base =
    "did:x509:0:sha256:oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8";

  // The prefix before the NUL must not match (no truncation at the NUL).
  test_resolve_error(
    chain,
    base + "::san:uri:https%3A%2F%2Ftrusted.example",
    "SAN not found");

  // The full value, including the percent-encoded NUL, matches exactly.
  test_resolve_success(
    chain,
    base +
      "::san:uri:https%3A%2F%2Ftrusted.example%00.attacker.test");
}

TEST_CASE("TestCNEmbeddedNulNotTruncated")
{
  // The certificate has CN = "trusted\x00evil" (embedded NUL).
  // has_common_name() must compare using the explicit ASN.1 length, not as a
  // NUL-terminated C string.  A certificate whose CN is "trusted\0evil" must
  // NOT compare equal to "trusted" (no truncation at the NUL), and MUST
  // compare equal to the full value including the NUL.
  UqX509 cert(load_certificate_chain("cn-embedded-nul.pem"));

  // The prefix before the NUL must not match (no truncation at the NUL).
  CHECK_FALSE(cert.has_common_name("trusted"));

  // The full value, including the embedded NUL, must match exactly.
  CHECK(cert.has_common_name(std::string("trusted\0evil", 12)));

  // An unrelated value must not match.
  CHECK_FALSE(cert.has_common_name("evil"));
}

TEST_CASE("TestCNUtf8Value")
{
  // The certificate has CN = "café Test", a non-ASCII UTF-8 value stored as
  // a UTF8String.  has_common_name() must decode it correctly via
  // ASN1_STRING_to_UTF8 rather than treating it as raw bytes.
  UqX509 cert(load_certificate_chain("cn-utf8.pem"));

  // Exact UTF-8 value must match.
  CHECK(cert.has_common_name("caf\xc3\xa9 Test"));

  // A lossy or partial representation must not match.
  CHECK_FALSE(cert.has_common_name("caf Test"));
  CHECK_FALSE(cert.has_common_name("cafe Test"));
}

TEST_CASE("TestSANNoSubjectFallback")
{
  // The leaf has only a URI SAN, but its subject CN is a hostname and its
  // subject contains an emailAddress attribute. X509_check_host /
  // X509_check_email would fall back to those subject fields when no SAN of
  // the matching type exists; the san policy must only consider SAN entries.
  auto chain = load_certificate_chain("san-subject-fallback.pem");
  const std::string base =
    "did:x509:0:sha256:oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8";

  // CN is "fallback.example.com" but there is no dNSName SAN.
  test_resolve_error(
    chain, base + "::san:dns:fallback.example.com", "SAN not found");

  // The subject has emailAddress="fallback@example.com" but no rfc822Name SAN.
  test_resolve_error(
    chain, base + "::san:email:fallback%40example.com", "SAN not found");

  // The actual URI SAN still matches (positive control).
  test_resolve_success(
    chain, base + "::san:uri:https%3A%2F%2Fexample.com%2Fanchor");
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

static std::vector<uint8_t> base64url_decode(const std::string& in)
{
  std::string b64 = in;
  std::replace(b64.begin(), b64.end(), '-', '+');
  std::replace(b64.begin(), b64.end(), '_', '/');
  const size_t pad = (4 - (b64.size() % 4)) % 4;
  b64.append(pad, '=');

  std::vector<uint8_t> out((b64.size() / 4) * 3);
  const int decoded_len = EVP_DecodeBlock(out.data(),
    reinterpret_cast<const unsigned char*>(b64.data()),
    static_cast<int>(b64.size()));
  if (decoded_len < 0)
    return {};

  size_t out_len = static_cast<size_t>(decoded_len);
  if (pad <= out_len)
    out_len -= pad;
  out.resize(out_len);
  return out;
}

TEST_CASE("TestEcJwkCoordinatePadding")
{
  // ec-leading-zero.pem has an EC P-256 leaf whose x coordinate begins with a
  // zero byte. RFC 7518 requires both coordinates to be encoded as the full
  // 32-octet field element, so the JWK must left-pad them rather than emit the
  // minimal (31-octet) big-endian integer encoding.
  auto chain = load_certificate_chain("ec-leading-zero.pem");
  auto did =
    "did:x509:0:sha256:SGI1ucfnPQ6_Rx2YIurUyv75tHSapBv2_aiXaGtxP8w"
    "::subject:CN:didx509cpp%20EC%20Test%20Leaf";

  auto doc = nlohmann::json::parse(resolve(chain, did, true));
  auto jwk = doc["verificationMethod"][0]["publicKeyJwk"];
  CHECK(jwk["kty"] == "EC");
  CHECK(jwk["crv"] == "P-256");

  const auto x = base64url_decode(jwk["x"].get<std::string>());
  const auto y = base64url_decode(jwk["y"].get<std::string>());
  CHECK(x.size() == 32);
  CHECK(y.size() == 32);
  // The fixture's leading zero byte must be preserved by the padding.
  CHECK(x.front() == 0x00);
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
