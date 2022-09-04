/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
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

#include "challenge/challenge-possession.hpp"
#include "requester-request.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/range/adaptor/map.hpp>

#include <iostream>

namespace ndncert::requester {

NDN_LOG_INIT(ndncert.cl);

class Client
{
public:
  Client(ndn::Name identity, std::vector<std::string> probeParams,
         std::string challenge, std::vector<std::string> challengeParams)
    : m_identity(std::move(identity))
    , m_probeParams(std::move(probeParams))
    , m_challenge(std::move(challenge))
    , m_challengeParams(std::move(challengeParams))
    , m_systemSignals(m_face.getIoService())
  {
  }

  void
  run(const CaProfile& ca)
  {
    m_trustedCert = *ca.cert;
    runDiscovery(ca.caPrefix, {});

    m_systemSignals.add(SIGINT);
    m_systemSignals.add(SIGTERM);
    m_systemSignals.async_wait([this] (auto&&... args) { handleSignal(std::forward<decltype(args)>(args)...); } );

    m_face.processEvents();
  }

private:
  void
  runDiscovery(const ndn::Name& caPrefix, const ndn::Name& fullCertName)
  {
    NDN_LOG_DEBUG("Run discovery for " << caPrefix);

    m_face.expressInterest(
      *Request::genCaProfileDiscoveryInterest(caPrefix),
      [this, fullCertName] (const auto&, const auto& data) {
        auto fetchingInterest = Request::genCaProfileInterestFromDiscoveryResponse(data);
        m_face.expressInterest(*fetchingInterest,
                              [this, fullCertName] (const auto&, const auto& data2) { infoCb(data2, fullCertName); },
                              [this] (auto&&...) { onNackCb(); },
                              [this] (auto&&...) { timeoutCb(); });
      },
      [this] (auto&&...) { onNackCb(); },
      [this] (auto&&...) { timeoutCb(); });
  }

  void
  infoCb(const Data& reply, const Name& certFullName)
  {
    CaProfile profile;
    try {
      if (certFullName.empty()) {
        if (m_trustedCert && !ndn::security::verifySignature(reply, *m_trustedCert)) {
          NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
        }
        profile = *Request::onCaProfileResponse(reply);
      }
      else {
        profile = *Request::onCaProfileResponseAfterRedirection(reply, certFullName);
      }
    }
    catch (const std::exception& e) {
      NDN_THROW_NESTED(std::runtime_error("The fetched CA information cannot be used because: "s + e.what()));
      return;
    }

    if (!m_identity.empty()) {
      // ready to request cert
      runNew(profile, m_identity);
    }
    else {
      runProbe(profile);
    }
  }

  void
  runProbe(const CaProfile& profile)
  {
    if (profile.probeParameterKeys.size() != m_probeParams.size()) {
      NDN_THROW(std::runtime_error("The number of PROBE parameters required by CA (" +
                                   std::to_string(profile.probeParameterKeys.size())
                                   + ") doesn't match the number of provided parmeters (" +
                                   std::to_string(m_probeParams.size()) + ")"));
    }

    auto keyIt = profile.probeParameterKeys.begin();
    auto valueIt = m_probeParams.begin();
    std::multimap<std::string, std::string> params;
    for (; keyIt != profile.probeParameterKeys.end() && valueIt != m_probeParams.end(); ++keyIt, ++valueIt) {
      params.emplace(*keyIt, *valueIt);
    }

    NDN_LOG_DEBUG("Run PROBE with [" << boost::algorithm::join(profile.probeParameterKeys, ", ") << "] parameters");

    m_face.expressInterest(*Request::genProbeInterest(profile, std::move(params)),
                          [this, profile] (const auto&, const auto& data) { probeCb(data, profile); },
                          [this] (auto&&...) { onNackCb(); },
                          [this] (auto&&...) { timeoutCb(); });
  }

  void
  probeCb(const Data& reply, CaProfile profile)
  {
    std::vector<std::pair<Name, int>> names;
    std::vector<Name> redirects;
    try {
      Request::onProbeResponse(reply, profile, names, redirects);
    }
    catch (const std::exception& e) {
      NDN_THROW_NESTED(std::runtime_error("The probed CA response cannot be used"));
    }

    if (!redirects.empty()) {
      auto redirectedCaFullName = redirects.front();
      auto redirectedCaName = ndn::security::extractIdentityFromCertName(redirectedCaFullName.getPrefix(-1));

      // run discovery again with the redirect
      runDiscovery(redirectedCaFullName, redirectedCaName);
    }
    else if (!names.empty()) {
      auto identity = names.front().first;
      runNew(profile, identity);
    }
    else {
      NDN_THROW(std::runtime_error("Neither name assignment nor redirection is available"));
      exit(1);
    }
  }

  void
  runNew(const CaProfile& profile, const Name& identityName)
  {
    // generate a newly key pair or choose an existing key
    const auto& pib = m_keyChain.getPib();
    ndn::security::pib::Identity identity;
    ndn::security::pib::Key key;
    try {
      identity = pib.getIdentity(identityName);
    }
    catch (const ndn::security::Pib::Error&) {
      identity = m_keyChain.createIdentity(identityName);
    }

    key = identity.getDefaultKey();
    NDN_LOG_DEBUG(">> NEW for " << key.getName());

    m_requesterState = std::make_shared<Request>(m_keyChain, profile, RequestType::NEW);
    auto interest = m_requesterState->genNewInterest(key.getName(),
                                                     time::system_clock::now(), time::system_clock::now() + 60_days);
    if (interest != nullptr) {
      m_face.expressInterest(*interest,
                           [this] (const auto&, const auto& data) { newCb(data); },
                           [this] (auto&&...) { onNackCb(); },
                           [this] (auto&&...) { timeoutCb(); });
    }
    else {
      NDN_THROW(std::runtime_error("Cannot generate the Interest for NEW step"));
    }
  }

  void
  newCb(const Data& reply)
  {
    std::list<std::string> challengeList;
    challengeList = m_requesterState->onNewRenewRevokeResponse(reply);

    if (challengeList.empty()) {
      NDN_THROW(std::runtime_error("There is no available challenge provided by the CA"));
    }

    if (m_challenge.empty()) {
      runChallenge(challengeList.front());
    }
    else {
      if (std::find(challengeList.begin(), challengeList.end(), m_challenge) != challengeList.end()) {
        runChallenge(m_challenge);
      }
      else {
        NDN_THROW(std::runtime_error("Challenge " + m_challenge + " not supported by the CA "
                                     "(advertized: " + boost::algorithm::join(challengeList, ", ") + ")"));
      }
    }
  }

  void
  runChallenge(const std::string& challengeType)
  {
    auto requirements = m_requesterState->selectOrContinueChallenge(challengeType);

    NDN_LOG_DEBUG("(Re-)run CHALLENGE " << challengeType << " with " << requirements.size()
                  << " requirements, current status: " << m_requesterState->m_status);
    for (const auto& req : requirements) {
      NDN_LOG_DEBUG("  - " << std::get<0>(req) << " (" << std::get<1>(req) << ")");
    }

    if (!requirements.empty()) {
      if (m_requesterState->m_status == Status::BEFORE_CHALLENGE) {

        if (requirements.size() != m_challengeParams.size()) {
          NDN_THROW(std::runtime_error("The number of challenge parameters required by CA doesn't match the number of provided parameters"));
        }

        auto keyIt = requirements.begin();
        auto valueIt = m_challengeParams.begin();
        for (; keyIt != requirements.end() && valueIt != m_challengeParams.end(); ++keyIt, ++valueIt) {
          // for known challenges, process semantically. For rest, just include the string value

          if (std::get<0>(*keyIt) == "issued-cert") {
            auto certName = *valueIt;
            auto idName = ndn::security::extractIdentityFromCertName(certName);
            auto keyName = ndn::security::extractKeyNameFromCertName(certName);
            Certificate cert = m_keyChain.getPib().getIdentity(idName).getKey(keyName).getCertificate(certName);
            m_requesterState->m_miscState.emplace("cert-name", ndn::Name(certName));

            std::get<1>(*keyIt) = std::string(reinterpret_cast<const char*>(cert.wireEncode().data()), cert.wireEncode().size());
          }
          else {
            std::get<1>(*keyIt) = *valueIt;
          }
        }
      }
      else if (m_requesterState->m_status == Status::CHALLENGE) {
        if (challengeType == "possession") {
          auto proofIt = requirements.find("proof");
          if (proofIt == requirements.end()) {
            NDN_THROW(std::runtime_error("Possession challenge is expected to have `proof` requirement, but it is missing"));
          }

          auto certIt = m_requesterState->m_miscState.find("cert-name");
          if (certIt == m_requesterState->m_miscState.end()) {
            NDN_THROW(std::runtime_error("Missing `cert-name` in the requester state"));
          }

          auto certName = boost::any_cast<ndn::Name>(certIt->second);
          auto keyName = ndn::security::extractKeyNameFromCertName(certName);
          auto signature = m_keyChain.getTpm().sign({m_requesterState->m_nonce},
                                                    keyName,
                                                    ndn::DigestAlgorithm::SHA256);
          proofIt->second = std::string(signature->get<char>(), signature->size());
        }
        //
        // for other challenges, will do some capture
        //
      }
    }

    m_face.expressInterest(*m_requesterState->genChallengeInterest(std::move(requirements)),
                           [this] (const auto&, const auto& data) { challengeCb(data); },
                           [this] (auto&&...) { onNackCb(); },
                           [this] (auto&&...) { timeoutCb(); });
  }

  void
  challengeCb(const Data& reply)
  {
    m_requesterState->onChallengeResponse(reply);

    if (m_requesterState->m_status == Status::SUCCESS) {
      NDN_LOG_DEBUG("Certificate has already been issued, download certificate");
      m_face.expressInterest(*m_requesterState->genCertFetchInterest(),
                             [this] (const auto&, const auto& data) { certFetchCb(data); },
                             [this] (auto&&...) { onNackCb(); },
                             [this] (auto&&...) { timeoutCb(); });
      return;
    }

    // ???
    runChallenge(m_requesterState->m_challengeType);
  }

  void
  certFetchCb(const Data& reply)
  {
    auto item = Request::onCertFetchResponse(reply);
    if (item) {
      m_keyChain.addCertificate(m_keyChain.getPib().getIdentity(item->getIdentity()).getKey(item->getKeyName()), *item);
    }
    m_face.getIoService().stop();
  }

  void
  onNackCb()
  {
    NDN_THROW(std::runtime_error("Got Nack"));
  }

  void
  timeoutCb()
  {
    // TODO make sure that it is not a critical
    NDN_THROW(std::runtime_error("Got Interest timeout"));
  }

  void
  handleSignal(const boost::system::error_code& error, int signalNum)
  {
    if (error) {
      return;
    }
    std::cerr << "Exiting on signal" << std::endl;
    m_face.getIoService().stop();
  }

private:
  ndn::Name m_identity;
  std::vector<std::string> m_probeParams;
  std::string m_challenge;
  std::vector<std::string> m_challengeParams;

  ndn::KeyChain m_keyChain;
  ndn::Face m_face{nullptr, m_keyChain};

  std::optional<Certificate> m_trustedCert;

  std::shared_ptr<Request> m_requesterState;

  boost::asio::signal_set m_systemSignals;
};


static int
main(int argc, char* argv[])
{
  namespace po = boost::program_options;
  std::string configFilePath = std::string(NDNCERT_SYSCONFDIR) + "/ndncert/client.conf";
  std::vector<std::string> probeParams;
  std::string challenge;
  std::vector<std::string> challengeParams;
  ndn::Name identity;

  po::options_description description("Usage: ndncert-client [-h] [-c FILE]\n");
  description.add_options()
    ("help,h", "produce help message")
    ("config-file,c", po::value<std::string>(&configFilePath), "configuration file of CA profile (must contain exactly one profile)")
    ("identity,i", po::value<ndn::Name>(&identity), "identity for the certificate (depends on CA profile)")
    ("probe-param,p", po::value<std::vector<std::string>>(&probeParams), "one or multiple parameters to determine identity name (in order selected CA expects them)")
    ("challenge", po::value<std::string>(&challenge), "Use the specified challenge (if not specified, the first offered challege will be used)")
    ("challenge-param,C", po::value<std::vector<std::string>>(&challengeParams), "one or multiple challenge-specific parameters")
    ;
  po::positional_options_description p;
  p.add("param", -1);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }

  if (!probeParams.empty() && !identity.empty()) {
    std::cerr << "ERROR: only either identity name or parameters can be specified\n" << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (probeParams.empty() && identity.empty()) {
    std::cerr << "ERROR: at least identity name or parameters must be specified\n" << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (vm.count("help") != 0) {
    std::cerr << description << std::endl;
    return 0;
  }

  ProfileStorage profileStorage;
  try {
    profileStorage.load(configFilePath);
  }
  catch (const std::exception& e) {
    std::cerr << "Cannot load the configuration file: " << e.what() << std::endl;
    exit(1);
  }

  std::optional<CaProfile> ca;
  if (profileStorage.getKnownProfiles().size() == 1) {
    ca = *profileStorage.getKnownProfiles().begin();
  }
  else {
    std::cerr << "ERROR: The configuration file must contain exactly one CA profile" << std::endl;
    exit(1);
  }

  Client client(identity, probeParams, challenge, challengeParams);

  try {
    client.run(*ca);
  }
  catch (const std::exception& e) {
    std::cerr << boost::diagnostic_information(e) << std::endl;
    return 1;
  }

  return 0;
}

} // namespace ndncert::requester

int
main(int argc, char* argv[])
{
  return ndncert::requester::main(argc, argv);
}
