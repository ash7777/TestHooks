#include "Hooks.h"

namespace TestHooks
{
	size_t FakeHandleCreator::m_nextHandle = 0x01000000;

	// Change these to static inline
	CloseHandleHook::CloseHandleType CloseHandleHook::fpCloseHandle;
	int CloseHandleHook::HookCount;
	std::vector<CloseHandleHook::Filter> CloseHandleHook::filters;

	// Change these to static inline
	SetupDiGetClassDevsWHook::SetupDiGetClassDevsWType SetupDiGetClassDevsWHook::fpSetupDiGetClassDevsW;
	int SetupDiGetClassDevsWHook::HookCount;
	std::vector<SetupDiGetClassDevsWHook::Filter> SetupDiGetClassDevsWHook::filters;
	int SetupDiGetClassDevsWHook::SerialPortCount;

	// Change these to static inline
	SetupDiEnumDeviceInfoHook::SetupDiEnumDeviceInfoType SetupDiEnumDeviceInfoHook::fpSetupDiEnumDeviceInfo;
	int SetupDiEnumDeviceInfoHook::HookCount;
	std::vector<SetupDiEnumDeviceInfoHook::Filter> SetupDiEnumDeviceInfoHook::filters;

	// Change these to static inline
	SetupDiDestroyDeviceInfoListHook::SetupDiDestroyDeviceInfoListType SetupDiDestroyDeviceInfoListHook::fpSetupDiDestroyDeviceInfoList;
	int SetupDiDestroyDeviceInfoListHook::HookCount;
	std::vector<SetupDiDestroyDeviceInfoListHook::Filter> SetupDiDestroyDeviceInfoListHook::filters;

	// Change these to static inline
	SetupDiGetDeviceRegistryPropertyHook::SetupDiGetDeviceRegistryPropertyType SetupDiGetDeviceRegistryPropertyHook::fpSetupDiGetDeviceRegistryProperty;
	int SetupDiGetDeviceRegistryPropertyHook::HookCount;
	std::vector<SetupDiGetDeviceRegistryPropertyHook::Filter> SetupDiGetDeviceRegistryPropertyHook::filters;

	// Change these to static inline
	SetupDiOpenDevRegKeyHook::SetupDiOpenDevRegKeyType SetupDiOpenDevRegKeyHook::fpSetupDiOpenDevRegKey;
	int SetupDiOpenDevRegKeyHook::HookCount;
	std::vector<SetupDiOpenDevRegKeyHook::Filter> SetupDiOpenDevRegKeyHook::filters;

	// Change these to static inline
	RegGetValueWHook::RegGetValueWType RegGetValueWHook::fpRegGetValueW;
	int RegGetValueWHook::HookCount;
	std::vector<RegGetValueWHook::Filter> RegGetValueWHook::filters;

	// Change these to static inline
	RegCloseKeyHook::RegCloseKeyType RegCloseKeyHook::fpRegCloseKey;
	int RegCloseKeyHook::HookCount;
	std::vector<RegCloseKeyHook::Filter> RegCloseKeyHook::filters;
}
