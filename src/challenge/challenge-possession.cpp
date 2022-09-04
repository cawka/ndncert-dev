/*
 * Copyright (c) 2017-2022, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "challenge-possession.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>

#include <iostream>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.possession);
NDNCERT_REGISTER_CHALLENGE(ChallengePossession, "possession");

const std::string ChallengePossession::PARAMETER_KEY_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengePossession::PARAMETER_KEY_NONCE = "nonce";
const std::string ChallengePossession::PARAMETER_KEY_PROOF = "proof";
const std::string ChallengePossession::NEED_PROOF = "need-proof";

ChallengePossession::ChallengePossession()
  : ChallengeModule("possession", 1, time::seconds(60))
{
}

void
ChallengePossession::readConfig(const JsonSection& config)
{
  auto anchorList = config.get_child("anchor-list", JsonSection());
  auto certValidatorCmd = config.get("cert-validator-cmd", ""s);
  size_t countOptions = !anchorList.empty() + !certValidatorCmd.empty();
  if (countOptions > 1) {
    NDN_THROW(std::runtime_error("Only one of `anchor-list` or `cert-validator-cmd` can be present in the config file"));
  }

  boost::property_tree::json_parser::write_json(std::cerr, config);

  if (!anchorList.empty()) {
      std::list<Certificate> trustAnchors;

      auto it = anchorList.begin();
      for (; it != anchorList.end(); it++) {
        std::istringstream ss(it->second.get("certificate", ""));
        auto cert = ndn::io::load<Certificate>(ss);
        if (cert == nullptr) {
          NDN_LOG_ERROR("Cannot load the certificate from config file");
          continue;
        }
        trustAnchors.push_back(*cert);
      }

      m_validateCertFunc = [trustAnchors] (const ndn::security::Certificate& cert) -> bool {
          auto keyLocator = cert.getSignatureInfo().getKeyLocator().getName();
          bool isOk = std::any_of(trustAnchors.begin(), trustAnchors.end(), [&] (const auto& anchor) {
            return (anchor.getKeyName() == keyLocator || anchor.getName() == keyLocator) &&
                   ndn::security::verifySignature(cert, anchor);
            });
          return isOk;
        };
  }
  else if (!certValidatorCmd.empty()) {
    m_validateCertFunc = [certValidatorCmd] (const ndn::security::Certificate& cert) -> bool {
      std::string command = certValidatorCmd;

      boost::process::opstream in;
      boost::process::ipstream debug;

      boost::process::child child(command, boost::process::std_in < in, boost::process::std_out > debug);
      in << cert.wireEncode();
      in.close();

      std::string line;
      while (child.running() && std::getline(debug, line)) {
        NDN_LOG_TRACE("Validate func `" << command << "`: " << line);
      }

      child.wait();

      NDN_LOG_TRACE("  exit code " << child.exit_code());
      return child.exit_code() == 0;
    };
  } else {
    NDN_THROW(std::runtime_error("`anchor-list` or `cert-validator-cmd` must be present in the config file"));
  }
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengePossession::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  BOOST_ASSERT(m_validateCertFunc);

  try {
    params.parse();

    Certificate credential;
    const uint8_t* signature = nullptr;
    size_t signatureLen = 0;
    const auto& elements = params.elements();
    for (size_t i = 0; i < elements.size() - 1; i++) {
      if (elements[i].type() == tlv::ParameterKey && elements[i + 1].type() == tlv::ParameterValue) {
        if (readString(elements[i]) == PARAMETER_KEY_CREDENTIAL_CERT) {
          try {
            credential.wireDecode(elements[i + 1].blockFromValue());
          }
          catch (const std::exception& e) {
            NDN_LOG_ERROR("Cannot load challenge parameter: credential " << e.what());
            return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                                   "Cannot challenge credential: credential."s + e.what());
          }
        }
        else if (readString(elements[i]) == PARAMETER_KEY_PROOF) {
          signature = elements[i + 1].value();
          signatureLen = elements[i + 1].value_size();
        }
      }
    }

    // verify the credential and the self-signed cert
    if (request.status == Status::BEFORE_CHALLENGE) {
      NDN_LOG_TRACE("Challenge Interest arrives. Check certificate and init the challenge");
      using ndn::toHex;

      // check the certificate
      if (!credential.hasContent() || signatureLen != 0) {
        return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Cannot find certificate");
      }
      if (!m_validateCertFunc(credential)) {
        return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Certificate cannot be verified");
      }

      // for the first time, init the challenge
      std::array<uint8_t, 16> secretCode{};
      ndn::random::generateSecureBytes(secretCode);
      JsonSection secretJson;
      secretJson.add(PARAMETER_KEY_NONCE, toHex(secretCode));
      const auto& credBlock = credential.wireEncode();
      secretJson.add(PARAMETER_KEY_CREDENTIAL_CERT, toHex({credBlock.wire(), credBlock.size()}));
      NDN_LOG_TRACE("Secret for request " << toHex(request.requestId) << " : " << toHex(secretCode));
      return returnWithNewChallengeStatus(request, NEED_PROOF, std::move(secretJson), m_maxAttemptTimes, m_secretLifetime);
    }
    else if (request.challengeState && request.challengeState->challengeStatus == NEED_PROOF) {
      NDN_LOG_TRACE("Challenge Interest (proof) arrives. Check the proof");
      //check the format and load credential
      if (credential.hasContent() || signatureLen == 0) {
        return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Cannot find certificate");
      }
      credential = Certificate(Block(ndn::fromHex(request.challengeState->secrets.get(PARAMETER_KEY_CREDENTIAL_CERT, ""))));
      auto secretCode = *ndn::fromHex(request.challengeState->secrets.get(PARAMETER_KEY_NONCE, ""));

      //check the proof
      ndn::security::transform::PublicKey key;
      key.loadPkcs8(credential.getPublicKey());
      if (ndn::security::verifySignature({secretCode}, {signature, signatureLen}, key)) {
        return returnWithSuccess(request);
      }
      return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                             "Cannot verify the proof of private key against credential.");
    }
  }
  catch (const std::exception& e) {
    // The server must not fail while processing exceptions!!!
    NDN_LOG_INFO("Error while processing challenge: " << boost::diagnostic_information(e));
    return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Fail to recognize the request (unknown error)");
  }

  NDN_LOG_TRACE("Proof of possession: bad state");
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Fail to recognize the request.");
}

// For Client
std::multimap<std::string, std::string>
ChallengePossession::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE) {
    result.emplace(PARAMETER_KEY_CREDENTIAL_CERT, "Please provide the certificate issued by a trusted CA.");
    return result;
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_PROOF) {
    result.emplace(PARAMETER_KEY_PROOF, "Please sign a Data packet with request ID as the content.");
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  return result;
}

Block
ChallengePossession::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                            const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 1) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    for (const auto& item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_CREDENTIAL_CERT) {
        request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CREDENTIAL_CERT));
        Block valueBlock(tlv::ParameterValue);
        auto& certTlvStr = std::get<1>(item);
        try {
          valueBlock.push_back(Block(ndn::make_span(reinterpret_cast<const uint8_t*>(certTlvStr.data()),
                                                    certTlvStr.size())));
        }
        catch (const ndn::Block::Error& e) {
          NDN_THROW(std::runtime_error("Wrong parameter value provided for `" + std::get<0>(item) + "` (" + e.what() + ")"));
        }

        request.push_back(valueBlock);
      }
      else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_PROOF) {
    if (params.size() != 1) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    for (const auto& item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_PROOF) {
        request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_PROOF));
        auto& sigTlvStr = std::get<1>(item);
        auto valueBlock = ndn::makeBinaryBlock(tlv::ParameterValue, sigTlvStr.data(), sigTlvStr.size());
        request.push_back(valueBlock);
      }
      else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}

void
ChallengePossession::fulfillParameters(std::multimap<std::string, std::string>& params,
                                       ndn::KeyChain& keyChain, const Name& issuedCertName,
                                       ndn::span<const uint8_t, 16> nonce)
{
  auto keyName = ndn::security::extractKeyNameFromCertName(issuedCertName);
  auto id = keyChain.getPib().getIdentity(ndn::security::extractIdentityFromCertName(issuedCertName));
  auto issuedCert = id.getKey(keyName).getCertificate(issuedCertName);
  const auto& issuedCertTlv = issuedCert.wireEncode();
  auto signature = keyChain.getTpm().sign({nonce}, keyName, ndn::DigestAlgorithm::SHA256);

  for (auto& [key, val] : params) {
    if (key == PARAMETER_KEY_CREDENTIAL_CERT) {
      val = std::string(reinterpret_cast<const char*>(issuedCertTlv.wire()), issuedCertTlv.size());
    }
    else if (key == PARAMETER_KEY_PROOF) {
      val = std::string(signature->get<char>(), signature->size());
    }
  }
}

} // namespace ndncert
