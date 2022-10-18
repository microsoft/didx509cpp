// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "didx509cpp.h"

#include <string>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

static const std::string test_data_dir = "../test/test-data/";

std::string esrp_chain = R"({
-----BEGIN CERTIFICATE-----
MIIGczCCBFugAwIBAgITMwAAABa66g9ymbWtqAAAAAAAFjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMScwJQYDVQQDEx5NaWNyb3NvZnQgUlNBIFRlc3RpbmcgUENBIDIwMjAwHhcNMjEwODI3MTcyNTU0WhcNMjIwODI1MTcyNTU0WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE4MDYGA1UEAxMvR2VuIFB1cnBvc2UgTm9DUyAzMDcyIDM4NCBUZXN0IDEgKERPIE5PVCBUUlVTVCkwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCjzxZua+KEdZHUuJbwQJmvgU2RjErw80aGb52VPTv7I9jnv979a1AeWdTWgDR4Kw7NcsimXIjqUuXYUfBMPW+2q3yZRo6kMph5hHw+5AO1OZmwhou02eOtM8JfwWU8H/0Q+Y2+SOvh55gCsyziD+c4k8FDI0SIJHkzcSpcqJclygAZln4ek0bHmxT+n2mqcKJuPoCmUP44Ld5HY7zG3G4OBbnyCAj043PHoYbVdUR6kWycLWtq+hHhFUD8Um1Zseges6Sy/0LkM12o+yKfEDM/y+0enJv1bKypfaheLPmKaV6Ro35hpstyv88jZmsbTK1tRAkNJSXLC76wsaJa/XkJeh+B2NXQxldtDtnuJxRPovdX9n4NHfQeC2cKJ8mQcQQw2m8IeomLhrmRJI5ld4sfehsmWCIDho50pifNzh+4ZAFmaR3BgyDI+H/JgE2yvTDNNzsJgTTnL5wulIwqEFT8h7liDA11JH2a+xNY4/FhoKFau9zYCSnBmqDMuf1iQwkCAwEAAaOCAX8wggF7MBUGA1UdJQQOMAwGCisGAQQBgjcKAw0wHQYDVR0OBBYEFLhn3JJQI0hBUIrYkDlrUDb0N6ruMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQLExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ2NzIxNSs0NjcyMzQwHwYDVR0jBBgwFoAU1QhTdcRmj9gzGp9srTz/FpHeRywwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwUlNBJTIwVGVzdGluZyUyMFBDQSUyMDIwMjAuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBSU0ElMjBUZXN0aW5nJTIwUENBJTIwMjAyMC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQwFAAOCAgEAGKB0/OSAyuCiNoqzX2I9OpgtftX+rSjs51rauN+fr3KP6bRnWtgQQZ7Vcmbz7TKwn2sGLA7YLZu5UsrhCsa/3hn1ixQwLGo1SzmMPsL019aiwec/fQrr8s+NRpA8MyUQxFby8XMx9eCP+zeqSvSM3noSKVbL+Yj5m9iWwzsZvRJFV8QwvlPzoL2aZ4RgwS2ROgCkzK3gHmiU7LJpur2S02EPDYadaLyahHrvEdyagh+qTXSeehteRclMsZSVX8+7R1DXAh5PK3yEmSyWVmhkAyOI0tA14rbAxqOTGPnEoIia71SYbOXshh8cxcZa9BSLPnWJ3cWr7NOIiQ6Jx/HeEvcAkC+dT54G2wkgvLF3yevx5wpb3ypu+h8/JHXpbMJvrUddxHY4vkd8zEsVJqyy5NHx0w6JhPLjahaRmA5hoAs1f4zj9znGpbKt2GungMfWvF7bY2wVKAIxj1zvl7QAUDMpfJpJhAMRVoBvnRu8/A1teluqUn8nUk2UhbCRX4MHKk4tje64inPnsOID36H9YzzwEDJe1XQxDar72DOoi/DE6OTF9DZHFvTMR7mJW1Tp6vIIpn0zOFjbMdywhHF5k17QrFQpK3EbhM+alzoZaVlywdVec9Lt+IFssjtDagJwzWSW/8CVwyNw0DI4Cc8JthWOtIhK77WGIKE+B74lxHA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
})";

using namespace didx509;

TEST_CASE("Wrong prefix")
{
  REQUIRE_THROWS(resolve(esrp_chain, "djd:y508:1:abcd::", true));
}

TEST_CASE("TestMaiksSubjectExample")
{
  REQUIRE_NOTHROW(resolve(
    esrp_chain,
    "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::"
    "subject:CN:Gen%20Purpose%20NoCS%203072%20384%20Test%201%20%28DO%20NOT%"
    "20TRUST%29",
    true));
}

TEST_CASE("TestMaiksEKUExample")
{
  REQUIRE_NOTHROW(resolve(
    esrp_chain,
    "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::"
    "eku:1.3.6.1.4.1.311.10.3.13",
    true));
}

TEST_CASE("TestMaiksFulcioEMailExample")
{
  std::string chain = R"(-----BEGIN CERTIFICATE-----
MIICODCCAb2gAwIBAgITVjcoGczLKMQtiNsui59WGCL4QTAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIy
MDUzMTE2NDMzOVoXDTIyMDUzMTE2NTMzOFowADBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABOem/bTrfwekS72AAnbUBsTvUmc6I+odVtNlBX13umRhTkpxwxdENn0W
LQ8ND4ANNVobVi5hpXYIiD/a9o0MvSyjgeswgegwDgYDVR0PAQH/BAQDAgeAMBMG
A1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOL/y1j+
WtvSQ8nIypnO2m9XOXG4MB8GA1UdIwQYMBaAFFjAHl+RRaVmqXrMkKGTItAqxcX6
MEgGA1UdEQEB/wQ+MDyBOndvcmtsb2FkLWlkZW50aXR5QHByaXlhLWNoYWluZ3Vh
cmQuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20wKQYKKwYBBAGDvzABAQQbaHR0cHM6
Ly9hY2NvdW50cy5nb29nbGUuY29tMAoGCCqGSM49BAMDA2kAMGYCMQCVYBmRKUQB
KfQf4MnUAuqn/jfaxyrYw/1iCP/5cHr3kqyqDLP1MxTJ3PzhXWHEWakCMQCOa8Bg
9hvCllR8Wxbgs63hZ3CAEqqvys7lpKjILZYZCvoV5h+zuW3u3P6DYIKzbsE=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----)";

  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:accounts.google.com"
    "::san:email:workload-identity%40priya-chainguard.iam.gserviceaccount.com",
    true));
}

TEST_CASE("TestMaiksFulcioGitHubActionsExample")
{
  auto chain = R"(-----BEGIN CERTIFICATE-----
MIIDLTCCArSgAwIBAgIUAJM2CzioU80JmzxgCvMHSSLB0q4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA1MDkwOTIyNDFaFw0yMjA1MDkwOTMyNDBaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATpg9yoDHYTCMQfcm48TToO3lSBRDGWuGFPu0NCGPa4J1fuVfmsbwIo
iMv54V09B0vx7MVGhT9qTEGmZAJMIMdho4IB4DCCAdwwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFHAi
gekLmhlk3slYoGlVw7GjlRCtMB8GA1UdIwQYMBaAFFjAHl+RRaVmqXrMkKGTItAq
xcX6MG4GA1UdEQEB/wRkMGKGYGh0dHBzOi8vZ2l0aHViLmNvbS9jaGFpbmd1YXJk
LWRldi9tb25vLy5naXRodWIvd29ya2Zsb3dzL3JldXNhYmxlLXByb3Zpc2lvbi55
YW1sQHJlZnMvaGVhZHMvbWFpbjAhBgorBgEEAYO/MAEFBBNjaGFpbmd1YXJkLWRl
di9tb25vMBIGCisGAQQBg78wAQIEBHB1c2gwLgYKKwYBBAGDvzABBAQgUHJvdmlz
aW9uIFN0YWdpbmcgSW5mcmFzdHJ1Y3R1cmUwOQYKKwYBBAGDvzABAQQraHR0cHM6
Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAdBgorBgEEAYO/
MAEGBA9yZWZzL2hlYWRzL21haW4wNgYKKwYBBAGDvzABAwQoYTA3ODFiOWQ1ZjZm
NjJiMjdmMzYzMTZhNzBmZmFjNGY4OTliZmVkMTAKBggqhkjOPQQDAwNnADBkAjAP
qj0JqXxpnBnCMYcUz0h6L2WxTjvQ817/1kDKuWU+0F6YDVCSVssenkg9Lpw2bloC
MEnDZJQS/rPDUwa8EOz+VA1gJnQo9xmep5R2RczLsTQZJEtKNVtZheXo4DPcjwmB
/Q==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----)";

  REQUIRE_NOTHROW(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::fulcio-issuer:token.actions.githubusercontent.com"
    "::san:uri:https%3A%2F%2Fgithub.com%2Fchainguard-dev%2Fmono%2F.github%"
    "2Fworkflows%2Freusable-provision.yaml%40refs%2Fheads%2Fmain",
    true));
}

static std::string load_certificate_chain(const std::string& path)
{
  std::ifstream t(test_data_dir + path);
  if (!t.good())
    throw std::runtime_error(std::string("could not open ") + path);
  std::stringstream ss;
  ss << t.rdbuf();
  return ss.str();
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
  REQUIRE_THROWS(resolve(
    chain, "did:x509:0:sha256:h::subject:CN:Microsoft%20Corporation", true));
}

TEST_CASE("TestInvalidCA")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS(
    resolve(chain, "did:x509:0:sha256:abc::CN:Microsoft%20Corporation", true));
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
  REQUIRE_THROWS(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:MicrosoftCorporation",
    true));
}

TEST_CASE("TestSubjectDuplicateField")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::subject:CN:Microsoft%20Corporation:CN:Microsoft%20Corporation",
    true));
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
  REQUIRE_THROWS(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::san:uri:igarcia%40suse.com",
    true));
}

TEST_CASE("TestSANInvalidValue")
{
  auto chain = load_certificate_chain("fulcio-email.pem");
  REQUIRE_THROWS(resolve(
    chain,
    "did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME"
    "::email:bob%40example.com",
    true));
}

TEST_CASE("TestBadEKU")
{
  auto chain = load_certificate_chain("ms-code-signing.pem");
  REQUIRE_THROWS(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.3.6.1.5.5.7.3.12",
    true));
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
  REQUIRE_THROWS(resolve(
    chain,
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE"
    "::eku:1.2.3",
    true));
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
