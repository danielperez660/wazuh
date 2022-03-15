/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TCP_ENDPOINT_H_
#define _TCP_ENDPOINT_H_

#include <cstring>
#include <functional>
#include <glog/logging.h>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <uvw/tcp.hpp>
#include <uvw/timer.hpp>

#include "baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver::endpoints
{

constexpr uint32_t CONNECTION_TIMEOUT_MSEC = 5000;

/**
 * @brief Implements tcp server endpoint using uvw library.
 *
 */
class TCPEndpoint : public BaseEndpoint
{
private:
    unsigned int m_port;
    std::string m_ip;

    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::TCPHandle> m_tcpHandle;

    void connectionHandler(uvw::TCPHandle & tcpHandle);

public:
    /**
     * @brief Construct a new TCPEndpoint object
     *
     * @param config
     * @param eventBuffer
     */
    explicit TCPEndpoint(const std::string & config, ServerOutput & eventBuffer);
    ~TCPEndpoint();

    void run() override;

    void close() override;
};

} // namespace engineserver::endpoints

#endif // _TCP_ENDPOINT_H_
