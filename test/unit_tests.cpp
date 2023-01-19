// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "didx509cpp.h"

#include <string>

#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest.h"

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

TEST_CASE("Wrong prefix")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(resolve(chain, "djd:y508:1:abcd::", true),
    doctest::Contains("unsupported method/prefix"));
}

TEST_CASE("Empty chain")
{
  REQUIRE_THROWS_WITH(resolve("", "djd:y508:1:abcd::", true),
    doctest::Contains("no certificate chain"));
}

TEST_CASE("TestRootCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation",
    true));
}

TEST_CASE("TestIntermediateCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:VtqHIq_ZQGb_4eRZVHOkhUiSuEOggn1T-32PSu7R4Ys"
    "::subject:CN:Microsoft%20Corporation",
    true));
}

TEST_CASE("TestInvalidLeafCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain, "did:x509:0:sha256:h::subject:CN:Microsoft%20Corporation", true),
    doctest::Contains("invalid certificate fingerprint"));
}

TEST_CASE("TestInvalidCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(
    resolve(chain, "did:x509:0:sha256:abc::CN:Microsoft%20Corporation", true),
    doctest::Contains("invalid certificate fingerprint"));
}

TEST_CASE("TestMultiplePolicies")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.5.5.7.3.3"
    "::eku:1.3.6.1.4.1.311.10.3.21",
    true));
}

TEST_CASE("TestSubject")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation",
    true));
}

TEST_CASE("TestSubjectInvalidName")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:MicrosoftCorporation",
    true),
    doctest::Contains("invalid subject key/value"));
}

TEST_CASE("TestSubjectDuplicateField")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:CN:Microsoft%20Corporation",
    true),
    doctest::Contains("duplicate field"));
}

TEST_CASE("TestSAN")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::san:email:igarcia%40suse.com",
    true));
}

TEST_CASE("TestSANInvalidType")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::san:uri:igarcia%40suse.com",
    true),
    doctest::Contains("SAN not found"));
}

TEST_CASE("TestSANInvalidValue")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::email:bob%40example.com",
    true),
    doctest::Contains("unsupported did:x509 scheme"));
}

TEST_CASE("TestBadEKU")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.5.5.7.3.12",
    true),
    doctest::Contains("EKU not found"));
}

TEST_CASE("TestGoodEKU")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.4.1.311.10.3.21",
    true));
}

TEST_CASE("TestEKUInvalidValue")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.2.3",
    true),
    doctest::Contains("EKU not found"));
}

TEST_CASE("TestFulcioIssuerWithEmailSAN")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:github.com%2Flogin%2Foauth"
    "::san:email:igarcia%40suse.com",
    true));
}

TEST_CASE("TestFulcioIssuerWithURISAN")
{
  auto chain = load_certificate_chain("fulcio-github-actions.pem");
  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:token.actions.githubusercontent.com"
    "::san:uri:https%3A%2F%2Fgithub.com%2Fbrendancassells%2Fmcw-continuous-"
    "delivery-lab-files%2F.github%2Fworkflows%2Ffabrikam-web.yml%40refs%"
    "2Fheads%2Fmain",
    true));
}

TEST_CASE("TestInvalidLeafOnly")
{
  auto chain = load_certificate_chain("containerplat-leaf.pem");
  REQUIRE_THROWS_WITH(resolve(
    chain,
    "did:x509:0:sha256:pDI-AL3g4rw3cHMC_dmMKpdzFF8JMFzWvfIzbK9_DbQ"
    "::eku:1.3.6.1.4.1.311.76.59.1.2",
    true), doctest::Contains("certificate chain too short"));
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