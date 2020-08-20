#include <Windows.h>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>
#include "MinHook/include/MinHook.h"

#include <setupapi.h>
#include <winreg.h>

namespace TestHooks
{
	class FakeHandleCreator
	{
	private:
		static size_t			m_nextHandle;
	public:
		FakeHandleCreator()
		{
		}

		size_t GetNextHandle()
		{
			return m_nextHandle++;
		}
	};

	class CloseHandleHook
	{
	private:
		using Filter = std::function<bool(const CloseHandleHook& hook, HANDLE handle, BOOL& result)>;

		typedef BOOL(WINAPI* CloseHandleType)(HANDLE);

		static CloseHandleType fpCloseHandle;
		static int HookCount;
		static std::vector<Filter> filters;

		static BOOL WINAPI DetourCloseHandle(HANDLE hObject)
		{
			return fpCloseHandle(hObject);
		}

		static BOOL WINAPI CloseHandleHandler(HANDLE hObject)
		{
			return DetourCloseHandle(hObject);
		}

	public:
		CloseHandleHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&CloseHandle, &DetourCloseHandle, reinterpret_cast<LPVOID*>(&fpCloseHandle));
				MH_EnableHook(&CloseHandle);
			}
			HookCount++;
		}

		~CloseHandleHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&CloseHandle);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class SetupDiGetClassDevsWHook
	{
	private:
		using Filter = std::function<bool(CONST GUID* ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags, HDEVINFO& result)>;

		typedef HDEVINFO(WINAPI* SetupDiGetClassDevsWType)(CONST GUID* ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags);

		static SetupDiGetClassDevsWType fpSetupDiGetClassDevsW;
		static int HookCount;
		static std::vector<Filter> filters;

		static int SerialPortCount;

		static HDEVINFO WINAPI DetourSetupDiGetClassDevsW(CONST GUID* ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags)
		{
			for (auto& filter : filters)
			{
				HDEVINFO result;
				if (filter(ClassGuid, Enumerator, hwndParent, Flags, result))
					return result;
			}
			return fpSetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
		}

	public:
		SetupDiGetClassDevsWHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&SetupDiGetClassDevsW, &DetourSetupDiGetClassDevsW, reinterpret_cast<LPVOID*>(&fpSetupDiGetClassDevsW));
				MH_EnableHook(&SetupDiGetClassDevsW);
			}
			HookCount++;
		}

		~SetupDiGetClassDevsWHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&SetupDiGetClassDevsW);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class SetupDiEnumDeviceInfoHook
	{
	private:
		using Filter = std::function<bool(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData, BOOL& result)>;

		typedef BOOL(WINAPI* SetupDiEnumDeviceInfoType)(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData);

		static SetupDiEnumDeviceInfoType fpSetupDiEnumDeviceInfo;
		static int HookCount;
		static std::vector<Filter> filters;

		static BOOL WINAPI DetourSetupDiEnumDeviceInfo(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData)
		{
			for (auto& filter : filters)
			{
				BOOL result;
				if (filter(DeviceInfoSet, MemberIndex, DeviceInfoData, result))
					return result;
			}
			return fpSetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);
		}

	public:
		SetupDiEnumDeviceInfoHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&SetupDiEnumDeviceInfo, &DetourSetupDiEnumDeviceInfo, reinterpret_cast<LPVOID*>(&fpSetupDiEnumDeviceInfo));
				MH_EnableHook(&SetupDiEnumDeviceInfo);
			}
			HookCount++;
		}

		~SetupDiEnumDeviceInfoHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&SetupDiEnumDeviceInfo);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class SetupDiDestroyDeviceInfoListHook
	{
	private:
		using Filter = std::function<bool(HDEVINFO DeviceInfoSet, BOOL& result)>;

		typedef BOOL(WINAPI* SetupDiDestroyDeviceInfoListType)(HDEVINFO DeviceInfoSet);

		static SetupDiDestroyDeviceInfoListType fpSetupDiDestroyDeviceInfoList;
		static int HookCount;
		static std::vector<Filter> filters;

		static BOOL WINAPI DetourSetupDiDestroyDeviceInfoList(HDEVINFO DeviceInfoSet)
		{
			for (auto& filter : filters)
			{
				BOOL result;
				if (filter(DeviceInfoSet, result))
					return result;
			}
			return fpSetupDiDestroyDeviceInfoList(DeviceInfoSet);
		}

	public:
		SetupDiDestroyDeviceInfoListHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&SetupDiDestroyDeviceInfoList, &DetourSetupDiDestroyDeviceInfoList, reinterpret_cast<LPVOID*>(&fpSetupDiDestroyDeviceInfoList));
				MH_EnableHook(&SetupDiDestroyDeviceInfoList);
			}
			HookCount++;
		}

		~SetupDiDestroyDeviceInfoListHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&SetupDiDestroyDeviceInfoList);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class SetupDiGetDeviceRegistryPropertyHook
	{
	private:
		using Filter = std::function<bool(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize, BOOL& result)>;

		typedef BOOL(WINAPI* SetupDiGetDeviceRegistryPropertyType)(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize);

		static SetupDiGetDeviceRegistryPropertyType fpSetupDiGetDeviceRegistryProperty;
		static int HookCount;
		static std::vector<Filter> filters;

		static BOOL WINAPI DetourSetupDiGetDeviceRegistryProperty(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
		{
			for (auto& filter : filters)
			{
				BOOL result;
				if (filter(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize, result))
					return result;
			}
			return fpSetupDiGetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
		}

	public:
		SetupDiGetDeviceRegistryPropertyHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&SetupDiGetDeviceRegistryProperty, &DetourSetupDiGetDeviceRegistryProperty, reinterpret_cast<LPVOID*>(&fpSetupDiGetDeviceRegistryProperty));
				MH_EnableHook(&SetupDiGetDeviceRegistryProperty);
			}
			HookCount++;
		}

		~SetupDiGetDeviceRegistryPropertyHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&SetupDiGetDeviceRegistryProperty);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class SetupDiOpenDevRegKeyHook
	{
	private:
		using Filter = std::function<bool(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Scope, DWORD HwProfile, DWORD KeyType, REGSAM samDesired, HKEY& result)>;

		typedef HKEY(WINAPI* SetupDiOpenDevRegKeyType)(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Scope, DWORD HwProfile, DWORD KeyType, REGSAM samDesired);

		static SetupDiOpenDevRegKeyType fpSetupDiOpenDevRegKey;
		static int HookCount;
		static std::vector<Filter> filters;

		static HKEY WINAPI DetourSetupDiOpenDevRegKey(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Scope, DWORD HwProfile, DWORD KeyType, REGSAM samDesired)
		{
			for (auto& filter : filters)
			{
				HKEY result;
				if (filter(DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, samDesired, result))
					return result;
			}
			return fpSetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, samDesired);
		}

	public:
		SetupDiOpenDevRegKeyHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&SetupDiOpenDevRegKey, &DetourSetupDiOpenDevRegKey, reinterpret_cast<LPVOID*>(&fpSetupDiOpenDevRegKey));
				MH_EnableHook(&SetupDiOpenDevRegKey);
			}
			HookCount++;
		}

		~SetupDiOpenDevRegKeyHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&SetupDiOpenDevRegKey);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class RegGetValueWHook
	{
	private:
		using Filter = std::function<bool(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData, LSTATUS& result)>;

		typedef LSTATUS(WINAPI* RegGetValueWType)(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

		static RegGetValueWType fpRegGetValueW;
		static int HookCount;
		static std::vector<Filter> filters;

		static LSTATUS WINAPI DetourRegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
		{
			for (auto& filter : filters)
			{
				LSTATUS result;
				if (filter(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData, result))
					return result;
			}
			return fpRegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
		}

	public:
		RegGetValueWHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&RegGetValueW, &DetourRegGetValueW, reinterpret_cast<LPVOID*>(&fpRegGetValueW));
				MH_EnableHook(&RegGetValueW);
			}
			HookCount++;
		}

		~RegGetValueWHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&RegGetValueW);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class RegCloseKeyHook
	{
	private:
		using Filter = std::function<bool(HKEY hKey, LSTATUS& result)>;

		typedef LSTATUS(WINAPI* RegCloseKeyType)(HKEY hKey);

		static RegCloseKeyType fpRegCloseKey;
		static int HookCount;
		static std::vector<Filter> filters;

		static LSTATUS WINAPI DetourRegCloseKey(HKEY hKey)
		{
			for (auto& filter : filters)
			{
				LSTATUS result;
				if (filter(hKey, result))
					return result;
			}
			return fpRegCloseKey(hKey);
		}

	public:
		RegCloseKeyHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&RegCloseKey, &DetourRegCloseKey, reinterpret_cast<LPVOID*>(&fpRegCloseKey));
				MH_EnableHook(&RegCloseKey);
			}
			HookCount++;
		}

		~RegCloseKeyHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&RegCloseKey);
		}

		void AddFilter(Filter newFilter)
		{
			filters.push_back(newFilter);
		}
	};

	class SerialPortHook
	{
	private:
		static const int FakeIteratorSignature = 0xcafebabe;
		class FakeIterator
		{
		private:
			struct DeviceInfo
			{
				GUID					m_classGuid;
				DWORD					m_deviceInstance;
				std::wstring				m_deviceDescription;

				DeviceInfo(GUID classGuid, DWORD deviceInstance, const std::wstring& deviceDescription)
					: m_classGuid(classGuid),
					m_deviceInstance(deviceInstance),
					m_deviceDescription(deviceDescription)
				{
				}
			};
			long						m_signature;
			std::vector<DeviceInfo>		m_devices;

		public:
			FakeIterator()
				: m_signature(FakeIteratorSignature)
			{
			}

			bool IsIndexValid(size_t deviceIndex) const
			{
				return deviceIndex < m_devices.size();
			}

			bool Validate()
			{
				return m_signature == FakeIteratorSignature;
			}

			void AddDeviceInfo(GUID classGuid, DWORD deviceInstance, const std::wstring& deviceDescription)
			{
				m_devices.emplace_back(classGuid, deviceInstance, deviceDescription);
			}

			bool GetItemAtIndex(size_t deviceIndex, PSP_DEVINFO_DATA DeviceInfoData) const
			{
				if (deviceIndex >= m_devices.size())
					return false;

				const DeviceInfo& entry = m_devices[deviceIndex];
				DeviceInfoData->ClassGuid = entry.m_classGuid;
				DeviceInfoData->DevInst = entry.m_deviceInstance;
				DeviceInfoData->Reserved = deviceIndex;

				return true;
			}

			std::wstring GetDescription(PSP_DEVINFO_DATA DeviceInfoData) const
			{
				size_t deviceIndex = DeviceInfoData->Reserved;
				assert(deviceIndex < m_devices.size());

				return m_devices[deviceIndex].m_deviceDescription;
			}
		};
		SetupDiGetClassDevsWHook				m_setupDiGetClassDevsWHook;
		SetupDiEnumDeviceInfoHook				m_setupDiEnumDeviceInfoHook;
		SetupDiDestroyDeviceInfoListHook		m_setupDiDestroyDeviceInfoListHook;
		SetupDiGetDeviceRegistryPropertyHook	m_setupDiGetDeviceRegistryPropertyHook;
		//	CreateFileHook							m_createFileHook;
		CloseHandleHook							m_closeHandleHook;;
		SetupDiOpenDevRegKeyHook				m_setupDiOpenDevRegKeyHook;
		RegGetValueWHook						m_regGetValueWHook;
		RegCloseKeyHook							m_regCloseKeyHook;
		FakeHandleCreator						m_fakeHandleCreator;
		std::vector<std::unique_ptr<FakeIterator>>	m_pendingIterators;
		std::map<HKEY, int>						m_pendingFakeHKEYs;
	public:
		SerialPortHook()
		{
			m_setupDiGetClassDevsWHook.AddFilter(std::bind(&SerialPortHook::SetupDiGetClassDevsWHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
			m_setupDiEnumDeviceInfoHook.AddFilter(std::bind(&SerialPortHook::SetupDiEnumDeviceInfoHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
			m_setupDiDestroyDeviceInfoListHook.AddFilter(std::bind(&SerialPortHook::DetourSetupDiDestroyDeviceInfoList, this, std::placeholders::_1));
			m_setupDiGetDeviceRegistryPropertyHook.AddFilter(std::bind(&SerialPortHook::DetourSetupDiGetDeviceRegistryProperty, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8));
			m_setupDiOpenDevRegKeyHook.AddFilter(std::bind(&SerialPortHook::DetourSetupDiOpenDevRegKey, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7));
			m_regGetValueWHook.AddFilter(std::bind(&SerialPortHook::DetourRegGetValueW, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8));
			m_regCloseKeyHook.AddFilter(std::bind(&SerialPortHook::DetourRegCloseKey, this, std::placeholders::_1, std::placeholders::_2));
		}

		~SerialPortHook()
		{
		}

		unsigned int AddSerialPort()
		{
			return 0;
		}

	private:
		static FakeIterator* HDEVINFOToFakeIterator(HDEVINFO DeviceInfoSet)
		{
			return reinterpret_cast<FakeIterator*>(DeviceInfoSet);
		}

		bool IsDeviceInfoSetAFake(HDEVINFO DeviceInfoSet) const
		{
			return (HDEVINFOToFakeIterator(DeviceInfoSet))->Validate();
		}

		void DestroyFakeIterator(HDEVINFO DeviceInfoSet)
		{
			for (auto& iterator = std::begin(m_pendingIterators); iterator != std::end(m_pendingIterators); ++iterator)
			{
				if (iterator->get() == DeviceInfoSet)
				{
					m_pendingIterators.erase(iterator);
					return;
				}
			}
			assert(false);
		}

		HDEVINFO ConstructNewFakeIterator()
		{
			HDEVINFO result = nullptr;

			std::unique_ptr<FakeIterator> newIterator = std::make_unique<FakeIterator>();

			GUID classGuid;
			newIterator->AddDeviceInfo(classGuid, 1, L"device description");

			result = reinterpret_cast<HDEVINFO>(newIterator.get());
			m_pendingIterators.push_back(std::move(newIterator));

			return result;
		}

		HKEY CreateNewFakeHKEY(const std::wstring& registryPath)
		{
			HKEY newHKEY = reinterpret_cast<HKEY>(m_fakeHandleCreator.GetNextHandle());
			m_pendingFakeHKEYs.insert(std::make_pair(newHKEY, 0));

			return newHKEY;
		}

		bool IsFakeHKEY(HKEY fakeRegKey)
		{
			auto iterator = m_pendingFakeHKEYs.find(fakeRegKey);
			return iterator != std::end(m_pendingFakeHKEYs);
		}

		void DestroyFakeHKEY(HKEY fakeRegKey)
		{
			auto iterator = m_pendingFakeHKEYs.find(fakeRegKey);
			assert(iterator != std::end(m_pendingFakeHKEYs));
			if (iterator != std::end(m_pendingFakeHKEYs))
				m_pendingFakeHKEYs.erase(iterator);
		}

		bool SetupDiGetClassDevsWHook(CONST GUID* ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags, HDEVINFO& result)
		{
			if (*ClassGuid == GUID_DEVINTERFACE_COMPORT)
			{
				result = ConstructNewFakeIterator();

				return true;
			}
			return false;
		}

		bool SetupDiEnumDeviceInfoHook(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData, BOOL& result)
		{
			if (IsDeviceInfoSetAFake(DeviceInfoSet))
			{
				if (DeviceInfoData->cbSize != sizeof(SP_DEVINFO_DATA))
				{
					SetLastError(ERROR_INVALID_USER_BUFFER);
					result = false;
					return true;
				}

				FakeIterator* fakeIterator = HDEVINFOToFakeIterator(DeviceInfoSet);
				if (!fakeIterator->IsIndexValid(MemberIndex))
					result = FALSE;
				else
				{
					fakeIterator->GetItemAtIndex(MemberIndex, DeviceInfoData);
					result = TRUE;
				}
				return true;
			}
			return false;
		}

		bool DetourSetupDiDestroyDeviceInfoList(HDEVINFO DeviceInfoSet)
		{
			if (IsDeviceInfoSetAFake(DeviceInfoSet))
			{
				DestroyFakeIterator(DeviceInfoSet);
				return true;
			}
			return false;
		}

		bool DetourSetupDiGetDeviceRegistryProperty(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize, BOOL& result)
		{
			if (IsDeviceInfoSetAFake(DeviceInfoSet))
			{
				FakeIterator* fakeIterator = HDEVINFOToFakeIterator(DeviceInfoSet);
				switch (Property)
				{
					case SPDRP_DEVICEDESC:
						{
							std::wstring value = fakeIterator->GetDescription(DeviceInfoData);
							size_t byteCount = (value.size() + 1) * sizeof(wchar_t);
							if (PropertyBuffer == nullptr)
							{
								if (PropertyBufferSize != 0)
									result = ERROR_MORE_DATA;
								else if (RequiredSize != nullptr)
									*RequiredSize = static_cast<DWORD>(byteCount);
							}
							else if (PropertyBufferSize < byteCount)
								result = ERROR_MORE_DATA;
							else
								memcpy(PropertyBuffer, value.c_str(), byteCount);
						}
						result = TRUE;
						break;

					default:
						assert(false);
						*RequiredSize = 0;
						break;
				}
				return true;
			}
			return false;
		}

		bool DetourSetupDiOpenDevRegKey(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Scope, DWORD HwProfile, DWORD KeyType, REGSAM samDesired, HKEY& result)
		{
			if (IsDeviceInfoSetAFake(DeviceInfoSet))
			{
				if (KeyType == DIREG_DEV && Scope == DICS_FLAG_GLOBAL)
				{
					result = CreateNewFakeHKEY(L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USB\\VID_10C4&PID_EA60\\0001\\Device Parameters");
					return true;
				}
				result = nullptr;
				SetLastError(1);
				return true;
			}
			return false;
		}

		bool DetourRegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData, LSTATUS& result)
		{
			if (IsFakeHKEY(hkey))
			{
				if ((lpSubKey == nullptr || *lpSubKey == 0) && wcscmp(lpValue, L"PortName") == 0)
				{
					if ((dwFlags & RRF_RT_REG_SZ) == 0)
					{
						result = 1;
						return true;
					}
					std::wstring value = L"COM4";
					size_t byteCount = (value.size() + 1) * sizeof(wchar_t);
					if (pvData == nullptr)
					{
						if (pcbData != nullptr)
							*pcbData = static_cast<DWORD>(byteCount);
					}
					else if (*pcbData < byteCount)
						result = ERROR_MORE_DATA;
					else
						memcpy(pvData, value.c_str(), byteCount);
					if (pdwType != nullptr)
						*pdwType = REG_SZ;
				}
				result = ERROR_SUCCESS;
				return true;
			}
			return false;
		}

		bool DetourRegCloseKey(HKEY hkey, LSTATUS& result)
		{
			if (IsFakeHKEY(hkey))
			{
				DestroyFakeHKEY(hkey);
				result = ERROR_SUCCESS;
				return true;
			}
			return false;
		}
	};
}
