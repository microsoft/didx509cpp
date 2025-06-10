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
  REQUIRE_NOTHROW(auto _ = nlohmann::json::parse(did_doc));
  
  std::string jwk;
  const auto split_chain = split_x509_cert_bundle(chain);
  REQUIRE_NOTHROW(jwk = resolve_jwk(split_chain, did, true));
  // Verify that resolved JWK is valid JSON
  REQUIRE_NOTHROW(auto _ = nlohmann::json::parse(jwk));
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
}

TEST_CASE("TestSubjectWithStateS")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  auto did =
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:S:Washington";
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
    if (strcmp(argv[i], "--data-dir") == 0 && i < argc - 1)
      test_data_dir = argv[i + 1];
  return ctx.run();
}