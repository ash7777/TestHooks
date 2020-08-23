#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>
#include <mutex>
#include <Windows.h>
#include "MinHook/include/MinHook.h"

#include <setupapi.h>
#include <winreg.h>

#undef AddMonitor

namespace TestHooks
{
	class FakeHandleCreator
	{
	private:
		static inline size_t			m_nextHandle { 0x01000000 };
	public:
		FakeHandleCreator()
		{
		}

		size_t GetNextHandle()
		{
			return m_nextHandle++;
		}
	};

	using FilterCookie = unsigned int;
	inline constexpr FilterCookie InvalidCookie { 0 };

	template<typename FilterType>
	class HookContainer
	{
	private:
		FilterCookie m_nextFilterCookie;
		std::map<FilterCookie, FilterType> m_filters;
		std::recursive_mutex m_mutex;
	public:
		HookContainer()
			: m_nextFilterCookie(1)
		{
		}

		~HookContainer()
		{
			assert(m_filters.empty());
		}

		FilterCookie AddFilter(FilterType newFilter)
		{
			std::lock_guard<std::recursive_mutex> lock(m_mutex);

			FilterCookie result = m_nextFilterCookie++;
			m_filters.insert(std::make_pair(result, newFilter));

			return result;
		}

		void RemoveFilter(FilterCookie cookie)
		{
			std::lock_guard<std::recursive_mutex> lock(m_mutex);

			auto iterator = m_filters.find(cookie);
			assert(iterator != std::end(m_filters));
			m_filters.erase(iterator);
		}

		template<typename FilterType>
		bool ForEachFilterReturningBoolean(FilterType doFilter)
		{
			std::lock_guard<std::recursive_mutex> lock(m_mutex);

			return std::any_of(std::begin(m_filters), std::end(m_filters), [&](auto& filterPair) {
					return doFilter(filterPair.second);
				});

			return false;
		}

		template<typename FilterType>
		void ForEachVoidFilter(FilterType doFilter)
		{
			std::lock_guard<std::recursive_mutex> lock(m_mutex);

			std::for_each(std::begin(m_filters), std::end(m_filters), [&](auto& filterPair) {
				doFilter(filterPair.second);
				});
		}
	};

	class CloseHandleHook
	{
	private:
		using Filter = std::function<bool(HANDLE handle, BOOL& result)>;
		using Monitor = std::function<void(HANDLE handle, BOOL result)>;

		typedef BOOL(WINAPI* CloseHandleType)(HANDLE);

		static inline CloseHandleType fpCloseHandle;
		static inline int HookCount;
		static inline HookContainer<Filter> m_filterHookContainer;
		static inline HookContainer<Monitor> m_monitorHookContainer;

		static BOOL WINAPI DetourCloseHandle(HANDLE hObject)
		{
			BOOL result;
			if (m_filterHookContainer.ForEachFilterReturningBoolean([&](Filter& filter) { return filter(hObject, result); }))
				return result;

			result = fpCloseHandle(hObject);
			m_monitorHookContainer.ForEachVoidFilter([&](Monitor& monitor) { monitor(hObject, result); });

			return result;
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

		FilterCookie AddFilter(Filter newFilter)
		{
			return m_filterHookContainer.AddFilter(newFilter);
		}

		void RemoveFilter(FilterCookie cookie)
		{
			m_filterHookContainer.RemoveFilter(cookie);
		}

		FilterCookie AddMonitor(Monitor newMonitor)
		{
			return m_monitorHookContainer.AddFilter(newMonitor);
		}

		void RemoveMonitor(FilterCookie cookie)
		{
			m_monitorHookContainer.RemoveFilter(cookie);
		}
	};

	class ReadFileHook
	{
	private:
		using Filter = std::function<bool(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped,
			LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, BOOL& result)>;
		using Monitor = std::function<void(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped,
			LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, BOOL result)>;

		typedef BOOL(WINAPI* ReadFileType)(HANDLE, LPVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);

		static inline ReadFileType fpReadFile;
		static inline int HookCount;
		static inline HookContainer<Filter> m_filterHookContainer;
		static inline HookContainer<Monitor> m_monitorHookContainer;

		static BOOL WINAPI DetourReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped,
			LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
		{
			BOOL result;
			if (m_filterHookContainer.ForEachFilterReturningBoolean([&](Filter& filter) { return filter(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine, result); }))
				return result;

			result = fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
			m_monitorHookContainer.ForEachVoidFilter([&](Monitor& monitor) { monitor(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine, result); });

			return result;
		}

	public:
		ReadFileHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&ReadFile, &DetourReadFile, reinterpret_cast<LPVOID*>(&fpReadFile));
				MH_EnableHook(&ReadFile);
			}
			HookCount++;
		}

		~ReadFileHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&ReadFile);
		}

		FilterCookie AddFilter(Filter newFilter)
		{
			return m_filterHookContainer.AddFilter(newFilter);
		}

		void RemoveFilter(FilterCookie cookie)
		{
			m_filterHookContainer.RemoveFilter(cookie);
		}

		FilterCookie AddMonitor(Monitor newMonitor)
		{
			return m_monitorHookContainer.AddFilter(newMonitor);
		}

		void RemoveMonitor(FilterCookie cookie)
		{
			m_monitorHookContainer.RemoveFilter(cookie);
		}
	};

	class WriteFileHook
	{
	private:
		using Filter = std::function<bool(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
			LPOVERLAPPED lpOverlapped, BOOL& result)>;
		using Monitor = std::function<void(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
			LPOVERLAPPED lpOverlapped, BOOL result)>;

		typedef BOOL(WINAPI* WriteFileType)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

		static inline WriteFileType fpWriteFile;
		static inline int HookCount;
		static inline HookContainer<Filter> m_filterHookContainer;
		static inline HookContainer<Monitor> m_monitorHookContainer;

		static BOOL WINAPI DetourWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
			LPOVERLAPPED lpOverlapped)
		{
			BOOL result;
			if (m_filterHookContainer.ForEachFilterReturningBoolean([&](Filter& filter) { return filter(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, result); }))
				return result;

			result = fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
			m_monitorHookContainer.ForEachVoidFilter([&](Monitor& monitor) { monitor(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, result); });

			return result;
		}

	public:
		WriteFileHook()
		{
			if (HookCount == 0)
			{
				MH_CreateHook(&WriteFile, &DetourWriteFile, reinterpret_cast<LPVOID*>(&fpWriteFile));
				MH_EnableHook(&WriteFile);
			}
			HookCount++;
		}

		~WriteFileHook()
		{
			HookCount--;
			if (HookCount == 0)
				MH_DisableHook(&WriteFile);
		}

		FilterCookie AddFilter(Filter newFilter)
		{
			return m_filterHookContainer.AddFilter(newFilter);
		}

		void RemoveFilter(FilterCookie cookie)
		{
			m_filterHookContainer.RemoveFilter(cookie);
		}

		FilterCookie AddMonitor(Monitor newMonitor)
		{
			return m_monitorHookContainer.AddFilter(newMonitor);
		}

		void RemoveMonitor(FilterCookie cookie)
		{
			m_monitorHookContainer.RemoveFilter(cookie);
		}
	};

	class CreateFileWHook
	{
	private:
		using Filter = std::function<bool(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
				LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
				HANDLE& result)>;
		using Monitor = std::function<void(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
			HANDLE result)>;

		typedef HANDLE(WINAPI* CreateFileType)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

		static inline CreateFileType fpCreateFile;
		static inline int m_hookCount;
		static inline HookContainer<Filter> m_filterHookContainer;
		static inline HookContainer<Monitor> m_monitorHookContainer;

		static HANDLE WINAPI DetourCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
		{
			HANDLE result;
			if (m_filterHookContainer.ForEachFilterReturningBoolean([&](Filter& filter) { return filter(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, result); }))
				return result;

			result = fpCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			m_monitorHookContainer.ForEachVoidFilter([&](Monitor& monitor) { monitor(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, result); });

			return result;
		}

	public:
		CreateFileWHook()
		{
			if (m_hookCount == 0)
			{
				MH_CreateHook(&CreateFileW, &DetourCreateFile, reinterpret_cast<LPVOID*>(&fpCreateFile));
				MH_EnableHook(&CreateFileW);
			}
			m_hookCount++;
		}

		~CreateFileWHook()
		{
			m_hookCount--;
			if (m_hookCount == 0)
				MH_DisableHook(&CreateFileW);
		}

		FilterCookie AddFilter(Filter newFilter)
		{
			return m_filterHookContainer.AddFilter(newFilter);
		}

		void RemoveFilter(FilterCookie cookie)
		{
			m_filterHookContainer.RemoveFilter(cookie);
		}

		FilterCookie AddMonitor(Monitor newMonitor)
		{
			return m_monitorHookContainer.AddFilter(newMonitor);
		}

		void RemoveMonitor(FilterCookie cookie)
		{
			m_monitorHookContainer.RemoveFilter(cookie);
		}
	};

	/// <summary>
	/// /////////////////////////////////////////////////////////////////////////////////
	/// </summary>
	class FileHook
	{
	private:
		CloseHandleHook				m_closeHandleHook;
		FilterCookie				m_closeHandleFilterCookie;
		FilterCookie				m_closeHandleMonitorCookie;
		CreateFileWHook				m_createFileWHook;
		FilterCookie				m_createFileWFilterCookie;
		FilterCookie				m_createFileWMonitorCookie;
		ReadFileHook				m_readFileHook;
		FilterCookie				m_readFileFilterCookie;
		FilterCookie				m_readFileMonitorCookie;
		WriteFileHook				m_writeFileHook;
		FilterCookie				m_writeFileFilterCookie;
		FilterCookie				m_writeFileMonitorCookie;

	public:
		FileHook()
			: m_closeHandleFilterCookie { InvalidCookie },
			  m_closeHandleMonitorCookie { InvalidCookie },
			  m_createFileWFilterCookie { InvalidCookie },
			  m_createFileWMonitorCookie { InvalidCookie },
			  m_readFileFilterCookie { InvalidCookie },
			  m_readFileMonitorCookie { InvalidCookie },
			  m_writeFileFilterCookie { InvalidCookie },
			  m_writeFileMonitorCookie { InvalidCookie }
		{
			m_closeHandleFilterCookie = m_closeHandleHook.AddFilter(std::bind(&FileHook::CloseHandleFilterHook, this, std::placeholders::_1, std::placeholders::_2));
			m_closeHandleMonitorCookie = m_closeHandleHook.AddMonitor(std::bind(&FileHook::CloseHandleMonitorHook, this, std::placeholders::_1, std::placeholders::_2));
			m_createFileWFilterCookie = m_createFileWHook.AddFilter(std::bind(&FileHook::CreateFileWFilterHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8));
			m_createFileWMonitorCookie = m_createFileWHook.AddMonitor(std::bind(&FileHook::CreateFileWMonitorHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8));
			m_readFileFilterCookie = m_readFileHook.AddFilter(std::bind(&FileHook::ReadFileFilterHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
			m_readFileMonitorCookie = m_readFileHook.AddMonitor(std::bind(&FileHook::ReadFileMonitorHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
			m_writeFileFilterCookie = m_writeFileHook.AddFilter(std::bind(&FileHook::WriteFileFilterHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
			m_writeFileMonitorCookie = m_writeFileHook.AddMonitor(std::bind(&FileHook::WriteFileMonitorHook, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
		}

		~FileHook()
		{
			m_closeHandleHook.RemoveFilter(m_closeHandleFilterCookie);
			m_closeHandleHook.RemoveMonitor(m_closeHandleMonitorCookie);
			m_createFileWHook.RemoveFilter(m_createFileWFilterCookie);
			m_createFileWHook.RemoveMonitor(m_createFileWMonitorCookie);
			m_readFileHook.RemoveFilter(m_readFileFilterCookie);
			m_readFileHook.RemoveMonitor(m_readFileMonitorCookie);
			m_writeFileHook.RemoveFilter(m_writeFileFilterCookie);
			m_writeFileHook.RemoveMonitor(m_writeFileMonitorCookie);
		}

	private:
		bool CloseHandleFilterHook(HANDLE handle, BOOL& result)
		{
			return false;
		}

		void CloseHandleMonitorHook(HANDLE handle, BOOL result)
		{
		}

		bool CreateFileWFilterHook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
			HANDLE& result)
		{
			return false;
		}

		void CreateFileWMonitorHook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
			HANDLE result)
		{
		}

		bool ReadFileFilterHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped,
			LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, BOOL& result)
		{
			return false;
		}

		void ReadFileMonitorHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped,
			LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, BOOL result)
		{
		}

		bool WriteFileFilterHook(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
			LPOVERLAPPED lpOverlapped, BOOL& result)
		{
			return false;
		}

		void WriteFileMonitorHook(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
			LPOVERLAPPED lpOverlapped, BOOL result)
		{
		}
	};

	class SetupDiGetClassDevsWHook
	{
	private:
		using Filter = std::function<bool(CONST GUID* ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags, HDEVINFO& result)>;

		typedef HDEVINFO(WINAPI* SetupDiGetClassDevsWType)(CONST GUID* ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags);

		static inline SetupDiGetClassDevsWType fpSetupDiGetClassDevsW;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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

		static inline SetupDiEnumDeviceInfoType fpSetupDiEnumDeviceInfo;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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

		static inline SetupDiDestroyDeviceInfoListType fpSetupDiDestroyDeviceInfoList;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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

		static inline SetupDiGetDeviceRegistryPropertyType fpSetupDiGetDeviceRegistryProperty;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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

		static inline SetupDiOpenDevRegKeyType fpSetupDiOpenDevRegKey;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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

		static inline RegGetValueWType fpRegGetValueW;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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

		static inline RegCloseKeyType fpRegCloseKey;
		static inline int HookCount;
		static inline std::vector<Filter> filters;

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
