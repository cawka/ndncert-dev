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

#include "challenge/challenge-module.hpp"

#include <ndn-cxx/util/random.hpp>

namespace ndncert {

ChallengeModule::ChallengeModule(const std::string& challengeType,
                                 size_t maxAttemptTimes,
                                 time::seconds secretLifetime)
  : CHALLENGE_TYPE(challengeType)
  , m_maxAttemptTimes(maxAttemptTimes)
  , m_secretLifetime(secretLifetime)
{
}

void
ChallengeModule::readConfig(const JsonSection& configSection)
{
}

bool
ChallengeModule::isChallengeSupported(const std::string& challengeType)
{
  auto& factory = getFactory();
  auto i = factory.find(challengeType);
  return i != factory.end();
}

std::unique_ptr<ChallengeModule>
ChallengeModule::createChallengeModule(const std::string& challengeType)
{
  auto& factory = getFactory();
  auto i = factory.find(challengeType);
  return i == factory.end() ? nullptr : i->second();
}

ChallengeModule::ChallengeFactory&
ChallengeModule::getFactory()
{
  static ChallengeFactory factory;
  return factory;
}

std::string
ChallengeModule::generateSecretCode()
{
  uint32_t securityCode = 0;
  do {
    securityCode = ndn::random::generateSecureWord32();
  } while (securityCode >= 4294000000);
  securityCode /= 4294;
  std::string result = std::to_string(securityCode);
  while (result.length() < 6) {
    result = "0" + result;
  }
  return result;
}

std::tuple<ErrorCode, std::string>
ChallengeModule::returnWithError(ca::RequestState& request, ErrorCode errorCode, std::string errorInfo)
{
  request.status = Status::FAILURE;
  request.challengeType = "";
  request.challengeState = std::nullopt;
  return {errorCode, std::move(errorInfo)};
}

std::tuple<ErrorCode, std::string>
ChallengeModule::returnWithNewChallengeStatus(ca::RequestState& request, const std::string& challengeStatus,
                                              JsonSection challengeSecret, size_t remainingTries,
                                              time::seconds remainingTime)
{
  request.status = Status::CHALLENGE;
  request.challengeType = CHALLENGE_TYPE;
  request.challengeState = ca::ChallengeState(challengeStatus, time::system_clock::now(), remainingTries,
                                              remainingTime, std::move(challengeSecret));
  return {ErrorCode::NO_ERROR, ""};
}

std::tuple<ErrorCode, std::string>
ChallengeModule::returnWithSuccess(ca::RequestState& request)
{
  request.status = Status::PENDING;
  request.challengeType = CHALLENGE_TYPE;
  request.challengeState = std::nullopt;
  return {ErrorCode::NO_ERROR, ""};
}

} // namespace ndncert
