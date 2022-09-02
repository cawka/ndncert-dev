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

#include "requester-request.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <iostream>

namespace ndncert::requester {

class Client
{
public:
  Client(ndn::Name identity, std::vector<std::string> params)
    : m_identity(std::move(identity))
    , m_params(std::move(params))
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
    m_face.expressInterest(
      *Request::genCaProfileDiscoveryInterest(caPrefix),
      [&] (const auto&, const auto& data) {
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
      // use probe and parameters to check name to request
//      NDN_THROW(std::runtime_error("PROBE request not implemented yet"));

      if (profile.probeParameterKeys.size() != m_params.size()) {
        NDN_THROW(std::runtime_error("The number of PROBE parameters required by CA (" +
                                     std::to_string(profile.probeParameterKeys.size())
                                     + ") doesn't match the number of provided parmeters (" +
                                     std::to_string(m_params.size()) + ")"));
      }

      auto keyIt = profile.probeParameterKeys.begin();
      auto valueIt = m_params.begin();
      std::multimap<std::string, std::string> params;
      for (; keyIt != profile.probeParameterKeys.end() && valueIt != m_params.end(); ++keyIt, ++valueIt) {
        params.emplace(*keyIt, *valueIt);
      }

      m_face.expressInterest(*Request::genProbeInterest(profile, std::move(params)),
                            [this, profile] (const auto&, const auto& data) { probeCb(data, profile); },
                            [this] (auto&&...) { onNackCb(); },
                            [this] (auto&&...) { timeoutCb(); });
    }
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
    auto interest = m_requesterState->genNewInterest(key.getName(),
                                                     time::system_clock::now(), time::system_clock::now() + 180_days);
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

    runChallenge(challengeList.front());
  }

  void
  runChallenge(const std::string& challengeType)
  {
    auto requirements = m_requesterState->selectOrContinueChallenge(challengeType);

    if (!requirements.empty()) {
      if (m_requesterState->m_status == Status::BEFORE_CHALLENGE) {
//        requirements.find(challengeType)->second = capturedProbeParams->find(defaultChallenge)->second;
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
//      std::cerr << "Certificate has already been issued, downloading certificate..." << std::endl;
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
  std::vector<std::string> m_params;

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
  std::vector<std::string> params;
  ndn::Name identity;

  po::options_description description("Usage: ndncert-client [-h] [-c FILE]\n");
  description.add_options()
    ("help,h", "produce help message")
    ("identity,i", po::value<ndn::Name>(&identity), "identity for the certificate (depends on CA profile)")
    ("config-file,c", po::value<std::string>(&configFilePath), "configuration file of CA profile (must contain exactly one profile)")
    ("param,p", po::value<std::vector<std::string>>(&params), "one or multiple parameters to determine identity name (in order selected CA expects them)")
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

  if (!params.empty() && !identity.empty()) {
    std::cerr << "ERROR: only either identity name or parameters can be specified\n" << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (params.empty() && identity.empty()) {
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

  Client client(identity, params);

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
