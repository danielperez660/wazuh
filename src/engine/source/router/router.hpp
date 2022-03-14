/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_H
#define _ROUTER_H

#include <algorithm>
#include <map>
#include <rxcpp/rx.hpp>
#include <string>
#include <type_traits>

#include "json.hpp"

namespace router
{

/**
 * @brief Represents a route and manages subscription
 *
 */
struct Route
{
    std::string m_name;
    std::string m_to;
    std::function<bool(json::Document)> m_from;
    rxcpp::composite_subscription m_subscription;

    Route() = default;
    Route(const Route & other) = delete;
    Route & operator=(const Route & other) = delete;

    /**
     * @brief Construct a new Route object
     *
     * @param name Name of the route
     * @param filter_function Filter events to send to environment
     * @param environment Environment name wich receives filtered events
     * @param subscription Subscription to handle status
     */
    Route(const std::string & name, const std::string & environment,
          std::function<bool(json::Document)> filter_function, rxcpp::composite_subscription subscription) noexcept
        : m_name(name), m_to(environment), m_from(filter_function), m_subscription(subscription)
    {
    }

    /**
     * @brief Construct a new Route object
     *
     * @param other
     */
    Route(Route && other) noexcept
        : m_name{std::move(other.m_name)}, m_to{std::move(other.m_to)}, m_from{std::move(other.m_from)},
          m_subscription{std::move(other.m_subscription)}
    {
    }

    /**
     * @brief Move assignation new Route object
     *
     * @param other
     * @return Route&
     */
    Route & operator=(Route && other) noexcept
    {
        this->m_name = std::move(other.m_name);
        this->m_from = std::move(other.m_from);
        this->m_to = std::move(other.m_to);
        this->m_subscription = std::move(other.m_subscription);
        return *this;
    }

    ~Route()
    {
        if (!this->m_subscription.get_weak().expired() && this->m_subscription.is_subscribed())
        {
            this->m_subscription.unsubscribe();
        }
    }
};

/**
 * @brief Defines environment as subject
 *
 */
struct Environment
{
    using Obs_t = rxcpp::observable<json::Document>;
    using Op_t = std::function<Obs_t(Obs_t)>;

    std::string m_name;
    rxcpp::subjects::subject<json::Document> m_subject;
    Op_t m_build;

    Environment() = default;

    /**
     * @brief Construct a new Environment object
     *
     * @param name Name of the environment
     * @param subject Subject of the built environment
     */
    Environment(const std::string & name, Op_t op) noexcept : m_name(name), m_build(op)
    {
    }
};

/**
 * @brief Router
 *
 * The Router manages the environments which are ready to be enabled, ie.
 * receive events from the server. Particularily, it can:
 *  - Create a new environment from its Catalog definition by calling the Builder
 *  - Route events received to an environment which is able to accept it
 *  - Enable an environment so it can accept events
 *  - Disable an environment so it can stop accepting events
 *
 * In case there is no environment enabled, the  router will drop the
 * events, freeing all resources associated to them.
 *
 * An environment is a set of decoders, rules, filters and outputs which are set
 * up to work together and a filter to decide which events to accept.
 *
 * @tparam Builder injected builder type to build environments
 */
template <class Builder> class Router
{
    using Obs_t = rxcpp::observable<json::Document>;
    using Op_t = std::function<Obs_t(Obs_t)>;

    // Check Builder class is as expected
    static_assert(std::is_invocable_r_v<Op_t, Builder, std::string>,
                  "Error, Router object expects a Builder callabe object with signature "
                  "rxcpp::subjects::subject<json::Document>(std::string)");

private:
    using ServerOutputObs = rxcpp::observable<rxcpp::observable<std::string>>;

    std::map<std::string, Environment> m_environments;
    std::map<std::string, Route> m_routes;
    rxcpp::subjects::subject<json::Document> m_subj;
    rxcpp::subscriber<json::Document> m_input;
    Builder m_builder;

public:
    /**
     * @brief Construct a new Router object
     *
     * @param builder Injected Builder object
     */
    Router(const Builder & builder) noexcept : m_builder{builder}, m_input{m_subj.get_subscriber()}
    {
    }

    /**
     * @brief Add a route
     *
     * @param environment Where events are forwarded
     * @param route Name of the route
     * @param filterFunction Filter function to select forwarded envent
     */
    void add(
        const std::string & route, const std::string & environment,
        const std::function<bool(json::Document)> filterFunction = [](const auto) { return true; })
    {
        // Assert route with same name not exists
        if (this->m_routes.count(route) > 0)
        {
            throw std::invalid_argument("Error, route " + route + " is already in use");
        }

        // Build environment if neccesary
        if (this->m_environments.count(environment) == 0)
        {
            Op_t envBuilder = this->m_builder(environment);
            this->m_environments[environment] = Environment(environment, envBuilder);

            // Build enviroment
            // TODO: handle errors/recovery, obs may be needed
            auto in = this->m_environments.at(environment).m_subject.get_observable();
            auto obs = envBuilder(in);
        }

        // Route filtered events to enviroment, Router subject implements multicasting (we need to
        // call get_observable for each filter added)
        auto envInput = this->m_environments.at(environment).m_subject.get_subscriber();
        auto subscription = this->m_subj.get_observable().filter(filterFunction).subscribe(envInput);

        // Add route to list
        this->m_routes[route] = Route(route, environment, filterFunction, subscription);
    }

    /**
     * @brief Delete route
     *
     * @param route Name of the route to be deleted
     */
    void remove(const std::string & route)
    {
        // Assert route exists
        if (this->m_routes.count(route) == 0)
        {
            throw std::invalid_argument("Error, route " + route + " can not be deleted because is not registered");
        }

        // Delete route and delete environment if not referenced by any other route
        std::string environment{this->m_routes[route].m_to};
        this->m_routes.erase(route);

        if (none_of(this->m_routes.cbegin(), this->m_routes.cend(),
                    [environment](const auto & r) { return r.second.m_to == environment; }))
        {
            this->m_environments.erase(environment);
        }
    }

    /**
     * @brief Obtain Router subscriber to inject events.
     *
     * @return const rxcpp::subscriber<json::Document>&
     */
    const rxcpp::subscriber<json::Document> & input() const
    {
        return this->m_input;
    }

    /**
     * @brief Get const reference of environments registered
     *
     * @return const std::map<std::string, Environment>&
     */
    const std::map<std::string, Environment> & environments() const noexcept
    {
        return this->m_environments;
    }

    /**
     * @brief Get const reference of routes registered
     *
     * @return const std::map<std::string, Route>
     */
    const std::map<std::string, Route> & routes() const noexcept
    {
        return this->m_routes;
    }
};

} // namespace router

#endif // _ROUTER_H
