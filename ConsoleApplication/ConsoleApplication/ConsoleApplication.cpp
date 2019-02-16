// ConsoleApplication.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <map>
#include <algorithm>

// запись хранилища
class StorageRecord
{
public:
	// производитель товара
	std::string producer;
	// наименование товара
	std::string name;
	// цена
	unsigned int price;
};

// потокобезопасный контейнер
template<typename T, typename mutex_t = std::recursive_mutex, typename x_lock_t =
	std::unique_lock<mutex_t>, typename s_lock_t = std::unique_lock<mutex_t >>
class StorageContainer 
{
	typedef mutex_t mtx_t;
	const std::shared_ptr<T> ptr;
	std::shared_ptr<mutex_t> mtx_ptr;

	// автолокер (автоматически блокирует объект при обращении через ->)
	template<typename req_lock>
	class AutoLocker 
	{
		T * const ptr;
		req_lock lock;
	public:
		AutoLocker(AutoLocker&& o) : ptr(std::move(o.ptr)), lock(std::move(o.lock)) { }
		AutoLocker(T * const _ptr, mutex_t& _mtx) : ptr(_ptr), lock(_mtx) {}
		T* operator -> () { return ptr; }
		const T* operator -> () const { return ptr; }
	};

	// автолокер (автоматически блокирует объект при обращении через *)
	template<typename req_lock>
	class AutoLockObject
	{
		T * const ptr;
		req_lock lock;
	public:
		AutoLockObject(AutoLockObject&& o) :
			ptr(std::move(o.ptr)), lock(std::move(o.lock)) { }
		AutoLockObject(T * const _ptr, mutex_t& _mtx) : ptr(_ptr), lock(_mtx) {}
		template<typename arg_t>
		auto operator [] (arg_t arg) -> decltype((*ptr)[arg]) { return (*ptr)[arg]; }
	};

	void lock() { mtx_ptr->lock(); }
	void unlock() { mtx_ptr->unlock(); }
	friend struct link_safe_ptrs;
	template<typename mutex_type> friend class std::lock_guard;

	public:
		template<typename... Args>
		StorageContainer(Args... args) : ptr(std::make_shared<T>(args...)), mtx_ptr(std::make_shared<mutex_t>()) {}

		AutoLocker<x_lock_t> operator-> () { return AutoLocker<x_lock_t>(ptr.get(), *mtx_ptr); }
		AutoLockObject<x_lock_t> operator * () { return AutoLockObject<x_lock_t>(ptr.get(), *mtx_ptr); }
		const AutoLocker<s_lock_t> operator-> () const { return auto_lock_t<s_lock_t>(ptr.get(), *mtx_ptr); }
		const AutoLockObject<s_lock_t> operator * () const { return auto_lock_obj_t<s_lock_t>(ptr.get(), *mtx_ptr); }
};


class Storage
{
private:
	StorageContainer <std::map<std::string, StorageRecord>> currentStorage;

public:

	Storage(){}
	
	void addRecord(std::string& vendorCode, StorageRecord &storageRecord)
	{
		currentStorage->insert(std::pair<std::string, StorageRecord>(vendorCode, storageRecord));
	}
	void removeRecord(std::string& vendorCode)
	{
		currentStorage->erase(vendorCode);
	}

	StorageRecord getRecord(std::string& vendorCode)
	{
		return currentStorage->find(vendorCode)->second;
	}

	std::vector<std::pair<std::string, StorageRecord>> getRecordsByProducer(std::string& producer)
	{
		std::vector<std::pair<std::string, StorageRecord>> records;
			
		for_each(currentStorage->cbegin(), currentStorage->cend(), [&](std::pair<std::string, StorageRecord> _pair)
		{
			if (_pair.second.producer == producer)
			{
				records.push_back(_pair);
			}
		});
		return records;
	}
private:
	Storage(Storage& s) {};
	Storage(Storage &&s) {};
	Storage(const Storage& s) {};
	Storage & operator=(const Storage& s);
	Storage&& operator = (Storage &&rhs);
};

int main()
{
	Storage storage;
	std::string vendorCode = "code";
	StorageRecord storageRecord;
	storage.addRecord(vendorCode, storageRecord);
    return 0;
}

