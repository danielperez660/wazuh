/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDBHELPER_HPP
#define _FIMDBHELPER_HPP
#include "fimDB.hpp"


namespace FIMDBHelper
{
    template<typename T>
    /**
    * @brief Init the FIM DB instance.
    *
    * @param syncInterval Interval when the sync is performed
    * @param syncCallback Synchronization callback.
    * @param logCallback Logging callback.
    * @param handlerDBSync DBSync handler.
    * @param handlerRSync RSync handler
    * @param fileLimit Max number of files.
    * @param registryLimit Max number of registries.
    * @param isWindows True if the OS is Windows
    */
    void initDB(const unsigned int syncInterval,
                fim_sync_callback_t syncCallback,
                logging_callback_t logCallback,
                std::shared_ptr<DBSync>handlerDBSync,
                std::shared_ptr<RemoteSync>handlerRSync,
                const unsigned int fileLimit,
                const unsigned int registryLimit = 0,
                const bool isWindows = false)
    {
        T::getInstance().init(syncInterval,
                              syncCallback,
                              logCallback,
                              handlerDBSync,
                              handlerRSync,
                              fileLimit,
                              registryLimit,
                              isWindows);
    }


    /**
    * @brief Delete a row from a table
    *
    * @param tableName a string with the table name
    * @param filter a string with a filter to delete an element to the database
    *
    */
    template<typename T>
    void removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        const auto deleteJsonStatement = R"({
                                                "table": "",
                                                "query": {
                                                }
        })";
        auto deleteJson = nlohmann::json::parse(deleteJsonStatement);
        deleteJson["table"] = tableName;
        deleteJson["query"]["data"] = nlohmann::json::array({filter});
        deleteJson["query"]["where_filter_opt"] = "";

        T::getInstance().removeItem(deleteJson);
    }

    /**
    * @brief Get count of all entries in a table
    *
    * @param tableName a string with the table name
    * @param count a int with count values
    * @param query a json to modify the query
    *
    */
    template<typename T>
    int getCount(const std::string& tableName, const nlohmann::json& query = {})
    {
        auto count { 0 };
        nlohmann::json countQuery;

        if (!query.empty())
        {
            countQuery = query;
        }
        else
        {
            const auto countQueryStatement = R"({
                                                    "table":"",
                                                    "query":{"column_list":["count(*) AS count"],
                                                    "row_filter":"",
                                                    "distinct_opt":false,
                                                    "order_by_opt":"",
                                                    "count_opt":100}
            })";
            countQuery = nlohmann::json::parse(countQueryStatement);
            countQuery["table"] = tableName;

        }

        auto callback
        {
            [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if (ReturnTypeCallback::SELECTED == type)
                {
                    count = jsonResult["count"];
                }
            }
        };
        T::getInstance().executeQuery(countQuery, callback);

        return count;
    }

    /**
    * @brief Insert or update a row from a table.
    *
    * @param item a json with a RegistryKey, RegistryValue or File with their parameters
    *
    * @return true if this operation was a update, false otherwise.
    */
    template<typename T>
    bool updateItem(const nlohmann::json& item)
    {
        auto result { false };

        const auto callback
        {
            [&result](ReturnTypeCallback type, const nlohmann::json&)
            {
                if (ReturnTypeCallback::MODIFIED == type)
                {
                    result = true;
                }
            }
        };

        T::getInstance().updateItem(item, callback);

        return result;
    }

    /**
    * @brief Get a item from a query
    *
    * @param item a json object where will be saved the query information
    * @param query a json with a query to the database
    *
    */
    template<typename T>
    void getDBItem(nlohmann::json& item, const nlohmann::json& query)
    {
        const auto callback
        {
            [&item](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if (ReturnTypeCallback::SELECTED == type)
                {
                    item = jsonResult;
                }
            }
        };

        T::getInstance().executeQuery(query, callback);
    }
}

#endif //_FIMDBHELPER_H