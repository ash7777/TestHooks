#define BOOST_TEST_MODULE MyTest
#include <boost/test/unit_test.hpp>
#include "Hooks.h"

BOOST_AUTO_TEST_CASE(CreateFile_)
{
	MH_Initialize();
	TestHooks::FileHook	fileHook;

	HANDLE handle = CreateFileW(L"test", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, nullptr);
	CloseHandle(handle);
}
