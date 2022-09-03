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

#include "detail/ca-request-state.hpp"

#include <ndn-cxx/util/indented-stream.hpp>

#include <boost/property_tree/json_parser.hpp>

namespace ndncert {

std::ostream&
operator<<(std::ostream& os, const Status& status)
{
  switch (status) {
  case Status::BEFORE_CHALLENGE:
    os << "Before challenge";
    break;
  case Status::CHALLENGE:
    os << "In challenge";
    break;
  case Status::PENDING:
    os << "Pending after challenge";
    break;
  case Status::SUCCESS:
    os << "Success";
    break;
  case Status::FAILURE:
    os << "Failure";
    break;
  default:
    os << "Unrecognized status";
    break;
  }
  return os;
}

Status
statusFromBlock(const Block& block)
{
  auto status_int = readNonNegativeInteger(block);
  if (status_int > 6)
      NDN_THROW(std::runtime_error("Unrecognized Status"));
  return static_cast<Status>(status_int);
}

namespace ca {

ChallengeState::ChallengeState(const std::string& challengeStatus,
                               const time::system_clock::TimePoint& challengeTp,
                               size_t remainingTries, time::seconds remainingTime,
                               JsonSection&& challengeSecrets)
  : challengeStatus(challengeStatus)
  , timestamp(challengeTp)
  , remainingTries(remainingTries)
  , remainingTime(remainingTime)
  , secrets(std::move(challengeSecrets))
{
}

std::ostream&
operator<<(std::ostream& os, const RequestState& request)
{
  os << "Request's CA name: " << request.caPrefix << "\n";
  os << "Request's request ID: " << ndn::toHex(request.requestId) << "\n";
  os << "Request's status: " << request.status << "\n";
  os << "Request's challenge type: " << request.challengeType << "\n";
  if (request.challengeState) {
    os << "Challenge Status: " << request.challengeState->challengeStatus << "\n";
    os << "Challenge remaining tries:" << request.challengeState->remainingTries << " times\n";
    os << "Challenge remaining time: " << request.challengeState->remainingTime.count() << " seconds\n";
    os << "Challenge last update: " << time::toIsoString(request.challengeState->timestamp) << "\n";
    std::stringstream ss;
    boost::property_tree::write_json(ss, request.challengeState->secrets);
    os << "Challenge secret: " << ss.str() << "\n";
  }
  os << "Certificate:\n";
  ndn::util::IndentedStream os2(os, "  ");
  os2 << request.cert;
  return os;
}

} // namespace ca
} // namespace ndncert
