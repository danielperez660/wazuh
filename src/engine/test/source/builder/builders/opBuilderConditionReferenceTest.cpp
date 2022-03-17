/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"

#include <vector>

#include "opBuilderConditionReference.hpp"

using namespace builder::internals::builders;

TEST(opBuilderConditionReference, Builds)
{
    Document doc{R"({
        "check":
            {"field": "$reference"}
    })"};
    ASSERT_NO_THROW(opBuilderConditionReference(doc.get("/check")));
}

TEST(opBuilderConditionReference, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":"value1",
                    "otherfield":"value1"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":"value1",
                    "otherfield":"value2"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->get("/field").GetString(), "value1");
    ASSERT_STREQ(expected[0]->get("/otherfield").GetString(), "value1");
}

TEST(opBuilderConditionReference, BuildsOperatesInt)
{
    Document doc{R"({
        "check":
            {"field": 1}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":2}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":1}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"1"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->get("/field").GetInt(), doc.get("/check").MemberBegin()->value.GetInt());
}

TEST(opBuilderConditionReference, BuildsOperatesBool)
{
    Document doc{R"({
        "check":
            {"field": true}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":false}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":true}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":1}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"1"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->get("/field").GetBool(), doc.get("/check").MemberBegin()->value.GetBool());
}

TEST(opBuilderConditionReference, BuildsOperatesNull)
{
    Document doc{R"({
        "check":
            {"field": null}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":null}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":true}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":1}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"1"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->get("/field"), rapidjson::Value{});
}

TEST(opBuilderConditionReference, BuildsOperatesArray)
{
    Document doc{R"({
        "check":
            {"field": [1, 2]}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":false}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":[1, 2]}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":1}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"1"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->get("/field").IsArray());
    ASSERT_EQ(expected[0]->get("/field").GetArray().Size(), doc.get("/check").MemberBegin()->value.GetArray().Size());
    for (auto eIt = expected[0]->get("/field").GetArray().Begin(),
              it = doc.get("/check").MemberBegin()->value.GetArray().Begin();
         eIt != expected[0]->get("/field").GetArray().End(); ++eIt, ++it)
    {
        ASSERT_EQ(*eIt, *it);
    }
}

TEST(opBuilderConditionReference, BuildsOperatesObject)
{
    Document doc{R"({
        "check":
            {"field": {
                "int": 1,
                "bool": false,
                "null": null,
                "string": "value"
            }}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field": {
                    "int": 1,
                    "bool": false,
                    "null": null,
                    "string": "value"
                }
            }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":true}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":1}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"1"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->get("/field").IsObject());
    for (auto eIt = expected[0]->get("/field").GetObj().MemberBegin(),
              it = doc.get("/check").MemberBegin()->value.GetObj().MemberBegin();
         eIt != expected[0]->get("/field").GetObj().MemberEnd(); ++eIt, ++it)
    {
        ASSERT_EQ(eIt->name, it->name);
        ASSERT_EQ(eIt->value, it->value);
    }
}

TEST(opBuilderConditionReference, BuildsOperatesOneLevel)
{
    Document doc{R"({
        "check":
            {"field.level": 1}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":2}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":{"level": 1}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":{"level": "1"}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->get("/field/level").GetInt(), doc.get("/check").MemberBegin()->value.GetInt());
}

TEST(opBuilderConditionReference, BuildsOperatesMultiLevel)
{
    Document doc{R"({
        "check":
            {"field.multi.level": 1}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":2}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field": {"multi": {"level": 1}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field": {"multi": {"level": "1"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->get("/field/multi/level").GetInt(), doc.get("/check").MemberBegin()->value.GetInt());
}
