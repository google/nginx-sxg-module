// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "ngx_sxg_utils.h"

#include <string>

#include "gtest/gtest.h"

namespace {

size_t TermLength(const std::string& input) {
  return get_term_length(input.data(), input.size(), ',', "<>");
}

TEST(NgxSxgUtilsTest, TermLength) {
  EXPECT_EQ(0, TermLength(""));
  EXPECT_EQ(4, TermLength("hoge,fuga"));
  EXPECT_EQ(11, TermLength("12<,,,,>345,abc"));
  EXPECT_EQ(4, TermLength("<>12,a"));
}

bool ShouldBeSXG(const std::string& input) {
  return sxg_qvalue_is_1(input.data(), input.size());
}

TEST(NgxSxgUtilsTest, ShouldBeSignedExchange) {
  EXPECT_TRUE(ShouldBeSXG("application/signed-exchange;v=b3"));
  EXPECT_TRUE(
      ShouldBeSXG("application/signed-exchange;v=b3,"
                  "application/signed-exchange;v=b3;q=0.9"));
  EXPECT_TRUE(
      ShouldBeSXG("application/signed-exchange;v=b3;q=0.9,"
                  "application/signed-exchange;v=b3"));
  EXPECT_TRUE(
      ShouldBeSXG("text/html;q=0.1,application/signed-exchange;Q=1;v=b3 "));
  EXPECT_TRUE(ShouldBeSXG("application/signed-exchange;V=\"b3\";Q=1"));
  EXPECT_TRUE(
      ShouldBeSXG("application/signed-exchange;v=b3; q=1. ,text/html;q=0.999"));
  EXPECT_TRUE(ShouldBeSXG(
      "application/signed-exchange;v=b3;q=1.000   ,text/html;q=0.999"));
  EXPECT_TRUE(ShouldBeSXG("application/signed-exchange;v=b3,text/html"));
  EXPECT_TRUE(ShouldBeSXG("*/*,text/html,application/signed-exchange;v=b3"));
  EXPECT_FALSE(ShouldBeSXG("v=b3"));
  EXPECT_FALSE(
      ShouldBeSXG("application/signed-exchange;q=0.9999;v=b3,text/html;q=0.5"));
  EXPECT_FALSE(
      ShouldBeSXG("application/signed-exchange;q=0.99a;v=b3,text/html;q=0.5"));
  EXPECT_FALSE(
      ShouldBeSXG("application/signed-exchange;q=0.8     ;v=b3,text/html;q=1"));
  EXPECT_FALSE(ShouldBeSXG("application/signed-exchange; v=b3 ; q=0.8 "));
  EXPECT_FALSE(ShouldBeSXG("application/signed-exchange;V=\"b3\";Q=0.8"));
  EXPECT_FALSE(ShouldBeSXG(
      "application/signed-exchange;v=b3;q=0.999,text/html;q=0.998"));
  EXPECT_FALSE(ShouldBeSXG("text/html"));
  EXPECT_FALSE(ShouldBeSXG("application/signed-exchange;v=b2"));
  EXPECT_FALSE(ShouldBeSXG("application/signed-exchange;v=;;,;;"));
  EXPECT_FALSE(ShouldBeSXG(";,Q,application/signed-exchange;;;v=\"\"\""));
  EXPECT_FALSE(ShouldBeSXG("application/signed-exchange;v=b3321"));
}

bool ParamIsPreload(const std::string& input) {
  return param_is_preload(input.data(), input.size());
}

TEST(NgxSxgUtilsTest, ParamIsPreload) {
  EXPECT_TRUE(ParamIsPreload("rel=preload"));
  EXPECT_TRUE(ParamIsPreload(" rel=preload"));
  EXPECT_TRUE(ParamIsPreload("rel=preload "));
  EXPECT_TRUE(ParamIsPreload("rel= preload"));
  EXPECT_TRUE(ParamIsPreload("rel =preload"));
  EXPECT_TRUE(ParamIsPreload("rel=\" preload\""));
  EXPECT_TRUE(ParamIsPreload("rel=\"preload \""));
  EXPECT_TRUE(ParamIsPreload("rel= \"preload\""));
  EXPECT_TRUE(ParamIsPreload(R"(rel="preload")"));
  EXPECT_TRUE(ParamIsPreload(R"(rel="alter preload hello world")"));
  EXPECT_FALSE(ParamIsPreload("preload=rel"));
  EXPECT_FALSE(ParamIsPreload("relative=preload"));
  EXPECT_FALSE(ParamIsPreload("rel="));
  EXPECT_FALSE(ParamIsPreload("rel ="));
  EXPECT_FALSE(ParamIsPreload("rel=\" = A\""));
  EXPECT_FALSE(ParamIsPreload("rel= "));
  EXPECT_FALSE(ParamIsPreload("rel=\"\n \""));
  EXPECT_FALSE(ParamIsPreload("r"));
  EXPECT_FALSE(ParamIsPreload("rel=preloa"));
  EXPECT_FALSE(ParamIsPreload("rel=prepreload"));
  EXPECT_FALSE(ParamIsPreload("rel = \"\"preload\""));
}

bool ParamIsAs(const std::string& input, const std::string& value) {
  const char* ptr;
  size_t len;
  bool result = param_is_as(input.data(), input.size(), &ptr, &len);
  return value == std::string(ptr, len) && result;
}

TEST(NgxSxgUtilsTest, ParamIsAs) {
  EXPECT_TRUE(ParamIsAs("as=script", "script"));
  EXPECT_TRUE(ParamIsAs("as=image", "image"));
  EXPECT_TRUE(ParamIsAs("as= script", "script"));
  EXPECT_TRUE(ParamIsAs("as =script", "script"));
  EXPECT_TRUE(ParamIsAs("as=script ", "script"));
  EXPECT_TRUE(ParamIsAs(" as=script", "script"));
  EXPECT_TRUE(ParamIsAs("as=\"script\"", "script"));
  EXPECT_TRUE(ParamIsAs("as=\" script\"", "script"));
  EXPECT_TRUE(ParamIsAs("as=\"script \"", "script"));
  EXPECT_FALSE(ParamIsAs("as=\" \"", ""));
  EXPECT_FALSE(ParamIsAs("as=\"", ""));
  EXPECT_FALSE(ParamIsAs("as= ", ""));
  EXPECT_FALSE(ParamIsAs("as!=script", ""));
  EXPECT_FALSE(ParamIsAs("as=script", "image"));
  EXPECT_FALSE(ParamIsAs("is=script", "script"));
  EXPECT_FALSE(ParamIsAs("as=scrpt", "script"));
}

TEST(NgxSxgCertChain, free) {
  ngx_sxg_cert_chain_t c = ngx_sxg_empty_cert_chain();
  ngx_sxg_cert_chain_release(&c);
}

TEST(NgxSxgCertChain, load) {
  ngx_sxg_cert_chain_t c = ngx_sxg_empty_cert_chain();

  EXPECT_TRUE(load_cert_chain("testdata/ocsp_included.pem", &c));

  ngx_sxg_cert_chain_release(&c);
}

TEST(NgxSxgCertChain, ocsp) {
  ngx_sxg_cert_chain_t c = ngx_sxg_empty_cert_chain();
  ASSERT_TRUE(load_cert_chain("testdata/ocsp_included.pem", &c));

  EXPECT_TRUE(refresh_if_needed(&c));
  EXPECT_FALSE(refresh_if_needed(&c));  // The OCSP Response is already hot.

  ngx_sxg_cert_chain_release(&c);
}

}  // namespace
