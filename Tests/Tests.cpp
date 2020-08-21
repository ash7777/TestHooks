#define BOOST_TEST_MODULE MyTest
#include <boost/test/unit_test.hpp>
#include "Hooks.h"

BOOST_AUTO_TEST_CASE(my_test)
{
	BOOST_REQUIRE(4 != 4);
}
