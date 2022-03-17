/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <vector>

#include "testUtils.hpp"
#include "opBuilderHelperMap.hpp"

using namespace builder::internals::builders;

TEST(opBuilderHelperIntCalc, Builds)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/sum/10"}
    })"};

    ASSERT_NO_THROW(opBuilderHelperIntCalc(doc.get("/normalice")));
}

TEST(opBuilderHelperIntCalc, Builds_error_bad_parameter)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/test/test"}
    })"};

    ASSERT_THROW(opBuilderHelperIntCalc(doc.get("/normalice")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Builds_error_less_parameters)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/10"}
    })"};

    ASSERT_THROW(opBuilderHelperIntCalc(doc.get("/normalice")), std::runtime_error);
}


TEST(opBuilderHelperIntCalc, Builds_error_more_parameters)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/10/10/10"}
    })"};

    ASSERT_THROW(opBuilderHelperIntCalc(doc.get("/normalice")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Builds_error_bad_operator)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/^/10"}
    })"};

    ASSERT_THROW(opBuilderHelperIntCalc(doc.get("/normalice")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Builds_error_zero_division)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/div/0"}
    })"};

    ASSERT_THROW(opBuilderHelperIntCalc(doc.get("/normalice")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Exec_equal_ok)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/sum/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 4);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),19);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),20);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),20);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),21);

}

TEST(opBuilderHelperIntCalc, Exec_sum_int)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/sum/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":100}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":-100}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),10);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),19);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),20);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),21);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),110);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),-90);

}

TEST(opBuilderHelperIntCalc, Exec_sub_int)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/sub/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":100}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":-100}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),-10);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),-1);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),1);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),90);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),-110);

}

TEST(opBuilderHelperIntCalc, Exec_mult_int)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/mul/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":100}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":-100}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),90);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),100);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),110);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),1000);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),-1000);

}

TEST(opBuilderHelperIntCalc, Exec_div_int)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/div/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":100}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":-100}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),1);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),1);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),10);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),-10);

}

TEST(opBuilderHelperIntCalc, Exec_sum_ref)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/sum/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":-10}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),10);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),19);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),20);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),21);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),-10);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),-1);
    ASSERT_EQ(expected[6]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[7]->get("/field_test").GetInt(),1);

}

TEST(opBuilderHelperIntCalc, Exec_sub_ref)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/sub/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":-10}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),-10);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),-1);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),1);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),10);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),19);
    ASSERT_EQ(expected[6]->get("/field_test").GetInt(),20);
    ASSERT_EQ(expected[7]->get("/field_test").GetInt(),21);

}

TEST(opBuilderHelperIntCalc, Exec_mult_ref)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/mul/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":-10}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),90);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),100);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),110);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),-90);
    ASSERT_EQ(expected[6]->get("/field_test").GetInt(),-100);
    ASSERT_EQ(expected[7]->get("/field_test").GetInt(),-110);

}

TEST(opBuilderHelperIntCalc, Exec_div_ref)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/div/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":-10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":-10}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),1);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),1);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[6]->get("/field_test").GetInt(),-1);
    ASSERT_EQ(expected[7]->get("/field_test").GetInt(),-1);

}

TEST(opBuilderHelperIntCalc, Exec_div_ref_zero)
{
    Document doc{R"({
        "normalice":
            {"field_test": "+i_calc/div/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 0,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src":0}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":0}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[1]->get("/field_test").GetInt(),9);
    ASSERT_EQ(expected[2]->get("/field_test").GetInt(),10);
    ASSERT_EQ(expected[3]->get("/field_test").GetInt(),11);
    ASSERT_EQ(expected[4]->get("/field_test").GetInt(),0);
    ASSERT_EQ(expected[5]->get("/field_test").GetInt(),9);
    ASSERT_EQ(expected[6]->get("/field_test").GetInt(),10);
    ASSERT_EQ(expected[7]->get("/field_test").GetInt(),11);

}

TEST(opBuilderHelperIntCalc, Exec_multilevel_dynamics_int_sum)
{
    Document doc{R"({
        "normalice":
            {"parentObjt_1.field2check": "+i_calc/sum/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                }
            )"));
            // not sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0]->get("/parentObjt_1/field2check").GetInt(), 21);
    ASSERT_EQ(expected[1]->get("/parentObjt_1/field2check").GetInt(), 20);
}

TEST(opBuilderHelperIntCalc, Exec_multilevel_dynamics_int_sub)
{
    Document doc{R"({
        "normalice":
            {"parentObjt_1.field2check": "+i_calc/sub/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                }
            )"));
            // not sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0]->get("/parentObjt_1/field2check").GetInt(), -1);
    ASSERT_EQ(expected[1]->get("/parentObjt_1/field2check").GetInt(), 0);
}

TEST(opBuilderHelperIntCalc, Exec_multilevel_dynamics_int_mul)
{
    Document doc{R"({
        "normalice":
            {"parentObjt_1.field2check": "+i_calc/mul/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                }
            )"));
            // not sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0]->get("/parentObjt_1/field2check").GetInt(), 110);
    ASSERT_EQ(expected[1]->get("/parentObjt_1/field2check").GetInt(), 100);
}

TEST(opBuilderHelperIntCalc, Exec_multilevel_dynamics_int_div)
{
    Document doc{R"({
        "normalice":
            {"parentObjt_1.field2check": "+i_calc/div/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                }
            )"));
            // not sorted
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIntCalc(doc.get("/normalice"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0]->get("/parentObjt_1/field2check").GetInt(), 0);
    ASSERT_EQ(expected[1]->get("/parentObjt_1/field2check").GetInt(), 1);
}
